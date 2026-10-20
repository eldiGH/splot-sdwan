//! The Linux key store: the node's secrets in a file of their own, readable by
//! root only.

use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

use super::file;
use crate::{
    backend::key_store::{KeyStore, KeyStoreError},
    model::host::HostRef,
    types::wg_key::{WgPresharedKey, WgPrivateKey},
    wg,
};

/// Where it is: in a directory of splot's own.
const PATH: &str = "/etc/splot/keys";

/// What the file says about itself, for whoever opens it.
const HEADER: &str = "\
# splot's key store: this node's WireGuard private key, and the preshared key
# of each of its pairs that has one, by peer. Written by `splot init` and
# `splot psk set`; readable by root only.
";
/// A line's first word: what it holds. `private-key <key>`, `psk <peer> <key>`.
const PRIVATE_KEY: &str = "private-key";
const PSK: &str = "psk";

/// What the file holds. Its private key may be missing only before `splot init`.
#[derive(Default)]
struct Keys {
    private_key: Option<WgPrivateKey>,
    /// By peer, as the config names it: `Cabin`, `Phone`, `Home.camera`.
    psks: BTreeMap<String, WgPresharedKey>,
}

impl Keys {
    /// The file's text, read from `path` (for its messages).
    fn parse(text: &str, path: &Path) -> Result<Self, KeyStoreError> {
        let mut keys = Self::default();

        for (index, line) in text.lines().enumerate() {
            let at = || format!("{}, line {}", path.display(), index + 1);
            let malformed = |problem| KeyStoreError::Malformed { at: at(), problem };

            match line.split_whitespace().collect::<Vec<_>>()[..] {
                [] => {}
                [first, ..] if first.starts_with('#') => {}
                [PRIVATE_KEY, key] => {
                    let key = key
                        .parse()
                        .map_err(|cause| KeyStoreError::InvalidPrivateKey { at: at(), cause })?;
                    if keys.private_key.replace(key).is_some() {
                        return Err(malformed("a second private key"));
                    }
                }
                [PSK, peer, key] => {
                    let key = key
                        .parse()
                        .map_err(|cause| KeyStoreError::InvalidPsk { at: at(), cause })?;
                    if keys.psks.insert(peer.to_owned(), key).is_some() {
                        return Err(malformed("a second preshared key for that peer"));
                    }
                }
                _ => return Err(malformed("not a line the key store holds")),
            }
        }

        Ok(keys)
    }

    /// As the file holds them.
    fn text(&self) -> String {
        let mut text = HEADER.to_owned();

        if let Some(key) = &self.private_key {
            text.push_str(&format!("{PRIVATE_KEY} {}\n", key.expose()));
        }
        for (peer, key) in &self.psks {
            text.push_str(&format!("{PSK} {peer} {}\n", key.expose()));
        }

        text
    }

    /// What the file at `path` holds; nothing when there's no file yet.
    fn read(path: &Path) -> Result<Self, KeyStoreError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(KeyStoreError::Read {
                at: path.display().to_string(),
                cause: err.into(),
            }),
        }
    }

    fn write(&self, path: &Path) -> Result<(), KeyStoreError> {
        file::write_private(path, &self.text()).map_err(|err| KeyStoreError::Write {
            at: path.display().to_string(),
            cause: err.into(),
        })
    }
}

/// The store at `path`, once it has a private key.
fn load(path: &Path) -> Result<FileKeyStore, KeyStoreError> {
    let Keys { private_key, psks } = Keys::read(path)?;

    Ok(FileKeyStore {
        private_key: private_key.ok_or(KeyStoreError::NotInitialised)?,
        psks,
    })
}

/// Stores `private_key` at `path`, keeping what else the store holds.
fn store_private_key(path: &Path, private_key: WgPrivateKey) -> Result<(), KeyStoreError> {
    let mut keys = Keys::read(path)?;
    keys.private_key = Some(private_key);
    keys.write(path)
}

/// Stores `key` for `peer` at `path`, in place of any it had, keeping the rest.
fn store_psk(path: &Path, peer: &HostRef, key: WgPresharedKey) -> Result<(), KeyStoreError> {
    let mut keys = Keys::read(path)?;
    keys.psks.insert(peer.to_string(), key);
    keys.write(path)
}

/// The node's key store on Linux, the file `/etc/splot/keys`: its private key,
/// and the preshared key of each of its pairs that has one, by peer.
pub struct FileKeyStore {
    private_key: WgPrivateKey,
    /// By peer, as the config names it (`HostRef`'s notation).
    psks: BTreeMap<String, WgPresharedKey>,
}

impl KeyStore for FileKeyStore {
    fn load() -> Result<Self, KeyStoreError> {
        load(&PathBuf::from(PATH))
    }

    fn create_private_key() -> Result<(), KeyStoreError> {
        store_private_key(&PathBuf::from(PATH), wg::generate_private_key()?)
    }

    fn store_psk(peer: &HostRef, key: &WgPresharedKey) -> Result<(), KeyStoreError> {
        store_psk(&PathBuf::from(PATH), peer, key.clone())
    }

    fn private_key(&self) -> &WgPrivateKey {
        &self.private_key
    }

    fn psk(&self, peer: &HostRef) -> Option<&WgPresharedKey> {
        self.psks.get(&peer.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, mode};

    const PRIVATE: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
    const CAMERA_PSK: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=";

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn camera() -> HostRef {
        HostRef::Local {
            node: "Home".parse().unwrap(),
            name: "camera".parse().unwrap(),
        }
    }

    fn phone() -> HostRef {
        HostRef::Client("Phone".parse().unwrap())
    }

    fn parse(text: &str) -> Result<Keys, KeyStoreError> {
        Keys::parse(text, Path::new("/etc/splot/keys"))
    }

    /// The store's keys, as text: the private key, then `peer key` per PSK.
    fn shown(store: &FileKeyStore) -> Vec<String> {
        let psk = |peer: HostRef| {
            store
                .psk(&peer)
                .map(|key| format!("{peer} {}", key.expose()))
        };
        [Some(store.private_key().expose().to_owned())]
            .into_iter()
            .chain([psk(cabin()), psk(camera()), psk(phone())])
            .flatten()
            .collect()
    }

    #[test]
    fn the_store_finds_each_pairs_psk_by_its_peer() {
        let dir = TempDir::new("linux-store-read");
        let path = dir.0.join("keys");
        fs::write(
            &path,
            format!(
                "# a comment\n\nprivate-key {PRIVATE}\npsk Cabin {CABIN_PSK}\n  psk Home.camera {CAMERA_PSK}\n"
            ),
        )
        .unwrap();

        let store = load(&path).unwrap();
        assert_eq!(
            shown(&store),
            [
                PRIVATE.to_owned(),
                format!("Cabin {CABIN_PSK}"),
                format!("Home.camera {CAMERA_PSK}"),
            ]
        );
    }

    #[test]
    fn what_the_store_writes_reads_back_the_same() {
        let dir = TempDir::new("linux-store-roundtrip");
        let path = dir.0.join("keys");

        store_psk(&path, &camera(), CAMERA_PSK.parse().unwrap()).unwrap();
        store_private_key(&path, PRIVATE.parse().unwrap()).unwrap();
        store_psk(&path, &cabin(), CABIN_PSK.parse().unwrap()).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!(
                "{HEADER}private-key {PRIVATE}\npsk Cabin {CABIN_PSK}\npsk Home.camera {CAMERA_PSK}\n"
            )
        );
        assert_eq!(mode(&path), 0o600);
        assert_eq!(shown(&load(&path).unwrap()).len(), 3);
    }

    #[test]
    fn a_psk_replaces_its_peers_old_one_and_keeps_the_rest() {
        let dir = TempDir::new("linux-store-replace");
        let path = dir.0.join("keys");
        store_private_key(&path, PRIVATE.parse().unwrap()).unwrap();
        store_psk(&path, &cabin(), CABIN_PSK.parse().unwrap()).unwrap();
        store_psk(&path, &phone(), CABIN_PSK.parse().unwrap()).unwrap();

        store_psk(&path, &cabin(), CAMERA_PSK.parse().unwrap()).unwrap();
        assert_eq!(
            shown(&load(&path).unwrap()),
            [
                PRIVATE.to_owned(),
                format!("Cabin {CAMERA_PSK}"),
                format!("Phone {CABIN_PSK}"),
            ]
        );
    }

    #[test]
    fn a_store_without_a_private_key_isnt_initialised() {
        let dir = TempDir::new("linux-store-uninitialised");
        let path = dir.0.join("keys");

        assert!(matches!(load(&path), Err(KeyStoreError::NotInitialised)));
        // Loading wrote nothing.
        assert!(!path.exists());

        store_psk(&path, &cabin(), CABIN_PSK.parse().unwrap()).unwrap();
        assert!(matches!(load(&path), Err(KeyStoreError::NotInitialised)));
    }

    #[test]
    fn a_line_the_store_doesnt_hold_is_refused_by_where_it_is() {
        let refused = |text: &str| match parse(text) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("{text:?} parsed"),
        };

        assert_eq!(
            refused(&format!("private-key {PRIVATE}\nprivate_key {PRIVATE}\n")),
            "/etc/splot/keys, line 2: not a line the key store holds - it holds `private-key <key>` and `psk <peer> <key>` lines, written by splot"
        );
        assert!(refused(&format!("psk {CABIN_PSK}\n")).contains("line 1: not a line"));
        assert!(refused(&format!("psk Cabin {CABIN_PSK} x\n")).contains("line 1: not a line"));
        assert!(
            refused(&format!("private-key {PRIVATE}\n\nprivate-key {PRIVATE}\n"))
                .contains("line 3: a second private key")
        );
        assert!(
            refused(&format!("psk Cabin {CABIN_PSK}\npsk Cabin {CAMERA_PSK}\n"))
                .contains("line 2: a second preshared key for that peer")
        );
    }

    #[test]
    fn a_stored_key_must_be_a_key() {
        let err = parse("private-key not-a-key\n").err().unwrap();
        assert!(
            matches!(&err, KeyStoreError::InvalidPrivateKey { at, .. } if at == "/etc/splot/keys, line 1"),
            "{err}"
        );

        let err = parse(&format!("private-key {PRIVATE}\npsk Cabin not-a-key\n"))
            .err()
            .unwrap();
        assert!(
            matches!(&err, KeyStoreError::InvalidPsk { at, .. } if at == "/etc/splot/keys, line 2"),
            "{err}"
        );
    }
}
