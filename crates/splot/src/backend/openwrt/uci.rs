//! Running uci on this peer.

use std::process::Command;

pub use splot_core::uci::UciBatchCommand;
use splot_core::uci::{UnsafeCommand, check};

use crate::{env, process};

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
    command.args(args);

    let output = process::run(command, stdin.map(str::as_bytes))?;

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
    #[error(transparent)]
    Unsafe(#[from] UnsafeCommand),
}

impl From<process::Error> for Error {
    fn from(err: process::Error) -> Self {
        match err {
            process::Error::Spawn(err) => Self::Spawn(err),
            process::Error::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_with_a_command_uci_cant_take_sends_nothing() {
        let batch = [
            UciBatchCommand::set("network.spl_x", "interface"),
            UciBatchCommand::set("network.spl_x.name", "a\nb"),
        ];
        assert!(matches!(batch_input(&batch), Err(Error::Unsafe(_))));
        assert_eq!(
            batch_input(&batch[..1]).unwrap(),
            "set network.spl_x='interface'\n"
        );
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
