use std::process::Command;

use splot_core::wg_key::{KeyFormatError, WgPrivateKey, WgPublicKey};

use crate::process;

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

/// Drops the peer whose public key is `public_key` from the live interface
/// `interface`, its session with it: the next reload adds it back, with a fresh
/// one.
pub fn remove_peer(interface: &str, public_key: &str) -> Result<(), Error> {
    run(&["set", interface, "peer", public_key, "remove"], None).map(drop)
}

/// When each peer of `interface` last completed a handshake with it, in
/// seconds since the epoch: 0 for never.
pub fn latest_handshakes(interface: &str) -> Result<Vec<(WgPublicKey, u64)>, Error> {
    Ok(handshakes(&run(
        &["show", interface, "latest-handshakes"],
        None,
    )?))
}

/// The peers and times in `wg show <interface> latest-handshakes`'s output: a
/// peer's public key and the time per line.
fn handshakes(output: &str) -> Vec<(WgPublicKey, u64)> {
    output
        .lines()
        .filter_map(|line| {
            let (key, time) = line.split_once('\t')?;
            Some((key.parse().ok()?, time.parse().ok()?))
        })
        .collect()
}

/// The public keys of this peer's WireGuard interfaces, whoever set them up.
/// Reads no private key.
pub fn interface_public_keys() -> Result<Vec<WgPublicKey>, Error> {
    Ok(public_keys(&run(&["show", "all", "public-key"], None)?))
}

/// The keys in `wg show all public-key`'s output: an interface and its public
/// key per line, `(none)` for one without a key.
fn public_keys(output: &str) -> Vec<WgPublicKey> {
    output
        .lines()
        .filter_map(|line| line.split('\t').nth(1)?.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_interface_with_a_key_gives_its_public_key() {
        let output = "spl_mesh\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
                      wg0\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\n\
                      wg1\t(none)\n";
        let keys = public_keys(output);
        let keys: Vec<&str> = keys.iter().map(WgPublicKey::as_str).collect();

        assert_eq!(
            keys,
            [
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
            ]
        );
        assert!(public_keys("").is_empty());
    }

    #[test]
    fn each_peer_gives_its_latest_handshake() {
        let output = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1729500000\n\
                      BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\t0\n";
        let read = handshakes(output);
        let read: Vec<(&str, u64)> = read
            .iter()
            .map(|(key, time)| (key.as_str(), *time))
            .collect();

        assert_eq!(
            read,
            [
                (
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    1_729_500_000
                ),
                ("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", 0)
            ]
        );
        assert!(handshakes("").is_empty());
    }
}
