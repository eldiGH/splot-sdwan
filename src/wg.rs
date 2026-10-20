use std::process::Command;

use crate::{
    process,
    types::wg_key::{KeyFormatError, WgPrivateKey, WgPublicKey},
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
    #[error("wg printed something that isn't a key")]
    NotAKey(#[source] KeyFormatError),
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

pub fn generate_private_key() -> Result<WgPrivateKey, Error> {
    run(&["genkey"], None)?.parse().map_err(Error::NotAKey)
}

pub fn get_pubkey(private_key: &WgPrivateKey) -> Result<WgPublicKey, Error> {
    run(&["pubkey"], Some(private_key.expose()))?
        .parse()
        .map_err(Error::NotAKey)
}
