use std::process::Command;

use crate::{
    process,
    types::wg_key::{KeyFormatError, check_key_format},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to run wg - is wireguard-tools installed?")]
    Spawn(#[source] std::io::Error),
    #[error("i/o error while talking to wg")]
    Io(#[source] std::io::Error),
    #[error("wg produced non-UTF-8 output")]
    NonUtf8,
    #[error("wg failed (exit code {code:?}): {stderr}")]
    Failed { code: Option<i32>, stderr: String },
}

impl From<process::Error> for Error {
    fn from(err: process::Error) -> Self {
        match err {
            process::Error::Spawn(err) => Self::Spawn(err),
            process::Error::Io(err) => Self::Io(err),
        }
    }
}

/// Runs `wg <args>`, optionally feeding `stdin`, and returns its trimmed stdout.
/// A non-zero exit is an error carrying wg's stderr — never an empty "result".
fn run(args: &[&str], stdin: Option<&str>) -> Result<String, Error> {
    let mut command = Command::new("wg");
    command.args(args);
    let output = process::run(command, stdin.map(str::as_bytes))?;

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

pub fn generate_private_key() -> Result<String, Error> {
    run(&["genkey"], None)
}

pub fn get_pubkey(private_key: &str) -> Result<String, Error> {
    run(&["pubkey"], Some(private_key))
}

/// Checks a stored private key's format. Private and public keys share one
/// format, so this is the same check `WgPublicKey` uses.
pub fn validate_private_key(private_key: &str) -> Result<(), KeyFormatError> {
    check_key_format(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The format rules themselves are tested in `types::wg_key`; these only pin
    // that private keys go through the same check.

    #[test]
    fn valid_key_passes() {
        assert!(validate_private_key("abcDEF0123456789+/abcDEF0123456789+/abcDEF0=").is_ok());
    }

    #[test]
    fn key_wg_would_reject_is_rejected() {
        // Passed the old shape-only check, but `wg pubkey` refuses it: the
        // character before '=' isn't canonical for 32 bytes.
        let key = format!("{}B=", "A".repeat(42));
        assert_eq!(
            validate_private_key(&key),
            Err(KeyFormatError::NonCanonical)
        );
    }
}
