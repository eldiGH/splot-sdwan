use std::{
    io::Write,
    process::{Command, Stdio},
};

use crate::env;

#[derive(Debug, Clone)]
pub enum UciBatchCommand {
    Set(String, String),
    Del(String),
    Add(String, String),
    AddList(String, String),
    Commit(Option<String>),
}

impl UciBatchCommand {
    pub fn set(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::Set(path.into(), val.into())
    }

    pub fn del(path: impl Into<String>) -> Self {
        Self::Del(path.into())
    }

    pub fn add(config: impl Into<String>, section: impl Into<String>) -> Self {
        Self::Add(config.into(), section.into())
    }

    pub fn add_list(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::AddList(path.into(), val.into())
    }

    pub fn commit(config: impl Into<String>) -> Self {
        Self::Commit(Some(config.into()))
    }

    pub fn redacted(&self) -> Self {
        if let Self::Set(path, ..) = self
            && path.ends_with(".private_key")
        {
            return Self::set(path, "<redacted>");
        }

        self.clone()
    }
}

impl std::fmt::Display for UciBatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(path, val) => write!(f, "set {path}='{val}'"),
            Self::Del(path) => write!(f, "delete {path}"),
            Self::Add(config, section) => write!(f, "add {config} {section}"),
            Self::AddList(path, val) => write!(f, "add_list {path}='{val}'"),

            Self::Commit(config) => {
                if let Some(config) = config {
                    write!(f, "commit {}", config)
                } else {
                    write!(f, "commit")
                }
            }
        }
    }
}

fn run(args: &[&str], stdin: Option<&str>) -> Result<String, Error> {
    let mut command = Command::new("uci");

    if let Some(uci_config_dir) = env::uci_config_dir() {
        command.arg("-c").arg(uci_config_dir);
    }

    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);

    let output = match stdin {
        Some(input) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().map_err(Error::Spawn)?;
            child
                .stdin
                .take()
                .expect("stdin was piped and not yet taken")
                .write_all(input.as_bytes())
                .map_err(Error::Io)?;
            child.wait_with_output().map_err(Error::Io)?
        }

        None => command.output().map_err(Error::Spawn)?,
    };

    if !output.status.success() {
        return Err(Error::Failed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        });
    }

    String::from_utf8(output.stdout)
        .map(|s| s.trim_end().to_owned())
        .map_err(|_| Error::NonUtf8)
}

// uci exits 1 with exactly this message whether the file, section or option is missing (verified
// with uci-git r590.g74f6277-1)
const ENTRY_NOT_FOUND: &str = "uci: Entry not found";

fn optional(result: Result<String, Error>) -> Result<Option<String>, Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Failed { stderr, .. }) if stderr == ENTRY_NOT_FOUND => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn batch(commands: &[UciBatchCommand]) -> Result<(), Error> {
    let input = commands
        .iter()
        .map(|cmd| format!("{cmd}\n"))
        .collect::<String>();

    run(&["batch"], Some(&input))?;

    Ok(())
}

pub fn show(file: &str) -> Result<Option<String>, Error> {
    optional(run(&["show", file], None))
}

pub fn get(path: &str) -> Result<Option<String>, Error> {
    optional(run(&["get", path], None))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to run uci - is it installed?")]
    Spawn(#[source] std::io::Error),
    #[error("i/o error while talking to uci")]
    Io(#[source] std::io::Error),
    #[error("uci produced non-UTF-8 output")]
    NonUtf8,
    #[error("uci failed (exit code {code:?}): {stderr}")]
    Failed { code: Option<i32>, stderr: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(cmd: &UciBatchCommand) -> String {
        cmd.to_string()
    }

    #[test]
    fn set_command() {
        assert_eq!(
            render(&UciBatchCommand::set("firewall.spl_rule", "rule")),
            "set firewall.spl_rule='rule'"
        );
    }

    #[test]
    fn del_command() {
        assert_eq!(
            render(&UciBatchCommand::del("firewall.spl_old")),
            "delete firewall.spl_old"
        );
    }

    #[test]
    fn add_command() {
        assert_eq!(
            render(&UciBatchCommand::add("firewall", "rule")),
            "add firewall rule"
        );
    }

    #[test]
    fn add_list_command() {
        assert_eq!(
            render(&UciBatchCommand::add_list(
                "firewall.spl_r.src_ip",
                "10.0.0.0/8"
            )),
            "add_list firewall.spl_r.src_ip='10.0.0.0/8'"
        );
    }

    #[test]
    fn commit_with_file() {
        assert_eq!(
            render(&UciBatchCommand::commit("firewall")),
            "commit firewall"
        );
    }

    #[test]
    fn commit_bare() {
        assert_eq!(render(&UciBatchCommand::Commit(None)), "commit");
    }

    #[test]
    fn value_with_spaces_is_quoted() {
        // The value is placed inside single-quotes; spaces inside are fine.
        let cmd = UciBatchCommand::set("network.spl_x.name", "hello world");
        assert_eq!(render(&cmd), "set network.spl_x.name='hello world'");
    }

    #[test]
    fn optional_passes_value_through() {
        let result = optional(Ok("value".to_owned()));
        assert!(matches!(result, Ok(Some(v)) if v == "value"));
    }

    #[test]
    fn optional_entry_not_found_becomes_none() {
        let result = optional(Err(Error::Failed {
            code: Some(1),
            stderr: ENTRY_NOT_FOUND.to_owned(),
        }));
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn optional_other_failure_stays_err() {
        // A parse error must NOT be classified as absence — a corrupt config
        // file must never look like a fresh install.
        let result = optional(Err(Error::Failed {
            code: Some(1),
            stderr: "uci: Parse error (invalid command) at line 3, byte 0".to_owned(),
        }));
        assert!(matches!(result, Err(Error::Failed { .. })));
    }

    #[test]
    fn optional_stderr_containing_not_found_is_not_none() {
        // Only the exact message counts; a superstring must stay an error.
        let result = optional(Err(Error::Failed {
            code: Some(1),
            stderr: format!("{ENTRY_NOT_FOUND}\nuci: Parse error"),
        }));
        assert!(matches!(result, Err(Error::Failed { .. })));
    }
}
