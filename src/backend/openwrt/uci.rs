use std::{
    io::Write,
    process::{Command, Stdio},
};

use crate::env;

#[derive(Debug, Clone)]
pub enum UciBatchCommand {
    Set(String, String),
    Del(String),
    AddList(String, String),
    /// Moves a section to a position among all sections of its file.
    Reorder(String, usize),
    Commit(Option<String>),
}

impl UciBatchCommand {
    pub fn set(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::Set(path.into(), val.into())
    }

    pub fn del(path: impl Into<String>) -> Self {
        Self::Del(path.into())
    }

    pub fn add_list(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::AddList(path.into(), val.into())
    }

    pub fn reorder(path: impl Into<String>, position: usize) -> Self {
        Self::Reorder(path.into(), position)
    }

    pub fn commit(config: impl Into<String>) -> Self {
        Self::Commit(Some(config.into()))
    }
}

/// Maps an identifier to a valid uci section/option name. uci accepts only
/// `[A-Za-z0-9_]` there, while identifiers may also contain `-`, so `-` becomes `_`.
pub fn name(identifier: &str) -> String {
    identifier.replace('-', "_")
}

/// A value in single quotes, the way uci's parser reads it back. A `'` inside
/// ends the quote, so it goes in escaped: `it's` is `'it'\''s'`. Unescaped, the
/// rest of the value would be read as more of the command.
fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Why `batch` won't send a command: a path with a character a uci name can't
/// have (paths aren't quoted), or a value with a control character. Every value
/// splot sends comes from a checked type, so this guards against bugs.
fn check(command: &UciBatchCommand) -> Result<(), Error> {
    let (path, value) = match command {
        UciBatchCommand::Set(path, value) | UciBatchCommand::AddList(path, value) => {
            (path.as_str(), Some(value))
        }
        UciBatchCommand::Del(path) | UciBatchCommand::Reorder(path, _) => (path.as_str(), None),
        UciBatchCommand::Commit(file) => (file.as_deref().unwrap_or_default(), None),
    };
    let unsafe_command = |reason| {
        Err(Error::Unsafe {
            path: path.to_owned(),
            reason,
        })
    };

    // A file, section and option name, or an anonymous section (`@rule[2]`).
    let name_char = |c: char| c.is_ascii_alphanumeric() || "_.@[]-".contains(c);
    if !path.chars().all(name_char) {
        return unsafe_command("a character uci names can't have");
    }
    if value.is_some_and(|value| value.chars().any(char::is_control)) {
        return unsafe_command("a control character in the value");
    }

    Ok(())
}

impl std::fmt::Display for UciBatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(path, val) => write!(f, "set {path}={}", quoted(val)),
            Self::Del(path) => write!(f, "delete {path}"),
            Self::AddList(path, val) => write!(f, "add_list {path}={}", quoted(val)),
            Self::Reorder(path, position) => write!(f, "reorder {path}={position}"),

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

/// What a successful uci call printed.
struct Output {
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&str>) -> Result<Output, Error> {
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

    let stderr = String::from_utf8_lossy(&output.stderr)
        .trim_end()
        .to_owned();

    if !output.status.success() {
        return Err(Error::Failed {
            code: output.status.code(),
            stderr,
        });
    }

    let stdout = String::from_utf8(output.stdout)
        .map(|s| s.trim_end().to_owned())
        .map_err(|_| Error::NonUtf8)?;

    Ok(Output { stdout, stderr })
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

/// `uci batch` exits 0 even when a line fails: it prints the error to stderr,
/// skips the line and carries on — a parse error even swallows the lines after it
/// (verified with uci-git r590.g74f6277-1). It prints nothing on success, so any
/// stderr output means uci did not apply what it was sent.
fn reject_on_stderr(stderr: &str) -> Result<(), Error> {
    if stderr.trim().is_empty() {
        Ok(())
    } else {
        Err(Error::Rejected {
            stderr: stderr.to_owned(),
        })
    }
}

/// What `batch` sends uci: one command a line, once each is checked.
fn batch_input(commands: &[UciBatchCommand]) -> Result<String, Error> {
    commands.iter().try_for_each(check)?;

    Ok(commands
        .iter()
        .map(|command| format!("{command}\n"))
        .collect())
}

/// Runs `commands` in one `uci batch`. Fails if uci rejected any line; the lines it
/// did accept stay staged (or committed, if the batch contained a commit).
pub fn batch(commands: &[UciBatchCommand]) -> Result<(), Error> {
    let output = run(&["batch"], Some(&batch_input(commands)?))?;

    reject_on_stderr(&output.stderr)
}

/// Writes the staged changes of `file` to the config file.
pub fn commit(file: &str) -> Result<(), Error> {
    let output = run(&["commit", file], None)?;

    reject_on_stderr(&output.stderr)
}

/// Drops the staged changes of `file`. A file uci doesn't know has nothing staged:
/// its "Entry not found" counts as done.
pub fn revert(file: &str) -> Result<(), Error> {
    match optional(run(&["revert", file], None).map(|output| output.stderr))? {
        Some(stderr) => reject_on_stderr(&stderr),
        None => Ok(()),
    }
}

/// Whether `file` has staged changes that aren't committed yet (`uci changes`).
pub fn has_changes(file: &str) -> Result<bool, Error> {
    let changes = optional(run(&["changes", file], None).map(|output| output.stdout))?;

    Ok(changes.is_some_and(|changes| !changes.is_empty()))
}

/// The file as `uci export` prints it; `None` when uci doesn't know the file.
pub fn export(file: &str) -> Result<Option<String>, Error> {
    optional(run(&["export", file], None).map(|output| output.stdout))
}

pub fn get(path: &str) -> Result<Option<String>, Error> {
    optional(run(&["get", path], None).map(|output| output.stdout))
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
    #[error("uci rejected part of the input: {stderr}")]
    Rejected { stderr: String },
    /// Names the path only: the value may be a key.
    #[error("refusing to send `{path}` to uci: {reason}")]
    Unsafe { path: String, reason: &'static str },
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
    fn a_quote_in_a_value_is_escaped_the_way_uci_reads_it() {
        assert_eq!(
            render(&UciBatchCommand::set("network.spl_x.name", "it's")),
            r"set network.spl_x.name='it'\''s'"
        );
        assert_eq!(
            render(&UciBatchCommand::add_list("network.spl_x.list", "a'b")),
            r"add_list network.spl_x.list='a'\''b'"
        );
    }

    #[test]
    fn a_quoted_value_reads_back_as_it_was() {
        // uci's file format quotes values the same way; the export parser reads
        // them the way uci does.
        for value in [
            "it's",
            "''",
            "a'b'c",
            r"back\slash",
            "spaces and ; set x.y=z",
        ] {
            let text = format!("package f\n\nconfig t 's'\n\toption o {}\n", quoted(value));
            let sections = super::super::export::parse(&text).unwrap();
            assert_eq!(
                sections[0].options,
                [(
                    "o".to_owned(),
                    super::super::section::Value::Single(value.to_owned())
                )],
                "{value}"
            );
        }
    }

    #[test]
    fn batch_refuses_a_control_character_or_a_path_uci_cant_name() {
        let refused = |command: UciBatchCommand| match check(&command) {
            Err(Error::Unsafe { path, .. }) => path,
            other => panic!("{command}: {other:?}"),
        };

        // The error names the path, never the value: it may be a key.
        assert_eq!(
            refused(UciBatchCommand::set("network.spl_x.key", "SECRET\nset x=1")),
            "network.spl_x.key"
        );
        assert_eq!(
            refused(UciBatchCommand::add_list("network.spl_x.l", "a\tb")),
            "network.spl_x.l"
        );
        assert_eq!(
            refused(UciBatchCommand::set("network.spl x.name", "v")),
            "network.spl x.name"
        );
        assert_eq!(
            refused(UciBatchCommand::del("network.spl_x;reboot")),
            "network.spl_x;reboot"
        );
        assert_eq!(
            refused(UciBatchCommand::reorder("network.spl_'x", 1)),
            "network.spl_'x"
        );
        let err = check(&UciBatchCommand::set("network.spl_x.key", "SECRET\n")).unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");

        // A batch with one such command sends nothing.
        let batch = [
            UciBatchCommand::set("network.spl_x", "interface"),
            UciBatchCommand::set("network.spl_x.name", "a\nb"),
        ];
        assert!(matches!(batch_input(&batch), Err(Error::Unsafe { .. })));
        assert_eq!(
            batch_input(&batch[..1]).unwrap(),
            "set network.spl_x='interface'\n"
        );

        // What splot sends.
        for command in [
            UciBatchCommand::set("network.spl_mesh.private_key", "ABC+/def="),
            UciBatchCommand::set(
                "network.spl_wireguard_spl_mesh_lte_cam",
                "wireguard_spl_mesh",
            ),
            UciBatchCommand::add_list("firewall.spl_rule_in_Home_ssh.src_ip", "10.0.0.0/8"),
            UciBatchCommand::set("firewall.spl_rule_in_Home_ssh.name", "[SPLOT] in: Home ssh"),
            UciBatchCommand::del("firewall.@rule[2]"),
            UciBatchCommand::reorder("network.spl_mesh", 7),
            UciBatchCommand::commit("network"),
        ] {
            assert!(check(&command).is_ok(), "{command}");
        }
    }

    #[test]
    fn value_with_spaces_is_quoted() {
        // The value is placed inside single-quotes; spaces inside are fine.
        let cmd = UciBatchCommand::set("network.spl_x.name", "hello world");
        assert_eq!(render(&cmd), "set network.spl_x.name='hello world'");
    }

    #[test]
    fn name_maps_hyphens_to_underscores() {
        // uci rejects '-' in section and option names ("uci: Invalid argument").
        assert_eq!(name("a-b-c"), "a_b_c");
        assert_eq!(name("plain_name"), "plain_name");
    }

    #[test]
    fn silent_batch_is_accepted() {
        assert!(reject_on_stderr("").is_ok());
        assert!(reject_on_stderr("\n").is_ok());
    }

    #[test]
    fn any_stderr_output_rejects_the_batch() {
        // `uci batch` exits 0 in all of these; stderr is the only signal.
        for stderr in [
            "uci: Invalid argument",
            "uci: Entry not found",
            "uci: Parse error (EOF with unterminated ') at line 2, byte 43",
        ] {
            let result = reject_on_stderr(stderr);
            assert!(
                matches!(&result, Err(Error::Rejected { stderr: s }) if s == stderr),
                "{stderr:?} → {result:?}"
            );
        }
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
