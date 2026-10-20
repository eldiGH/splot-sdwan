//! The OpenWrt key store: the node's secrets in a uci file of their own.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use super::{
    export,
    naming::UciSectionName,
    section::{Section, Value},
    uci::{self, UciBatchCommand},
};
use crate::{
    backend::key_store::{KeyStore, KeyStoreError},
    env,
    model::host::HostRef,
    types::wg_key::{WgPresharedKey, WgPrivateKey},
    wg,
};

/// The uci file that holds the node's secrets.
const FILE: &str = "splot";
/// The option that holds its private key.
const PRIVATE_KEY: &str = "splot.config.private_key";
/// The section type of a stored preshared key, and its option that holds it.
const PSK_TYPE: &str = "psk";
const PSK_KEY: &str = "key";

/// The section that holds the preshared key of the node's pair with `peer`, named
/// the way splot names the peer's own section, so a peer has at most one.
fn psk_section(peer: &HostRef) -> UciSectionName {
    UciSectionName::new([PSK_TYPE, peer.name().as_ref()])
}

/// The preshared keys among the store's sections, by section name. A section
/// without a key holds none.
fn psks(sections: &[Section]) -> Result<BTreeMap<String, WgPresharedKey>, KeyStoreError> {
    let mut psks = BTreeMap::new();

    for section in sections
        .iter()
        .filter(|section| section.section_type == PSK_TYPE)
    {
        let key = section
            .options
            .iter()
            .find_map(|(option, value)| match value {
                Value::Single(key) if option == PSK_KEY => Some(key),
                _ => None,
            });
        if let Some(key) = key {
            let key = key.parse().map_err(|cause| KeyStoreError::InvalidPsk {
                at: format!("{FILE}.{}", section.name),
                cause,
            })?;
            psks.insert(section.name.clone(), key);
        }
    }

    Ok(psks)
}

/// The commands that store `key` as the preshared key of the node's pair with
/// `peer`, in place of any it had.
fn store_psk_commands(peer: &HostRef, key: &WgPresharedKey) -> Vec<UciBatchCommand> {
    let section = psk_section(peer);

    vec![
        UciBatchCommand::set(format!("{FILE}.{section}"), PSK_TYPE),
        UciBatchCommand::set(format!("{FILE}.{section}.{PSK_KEY}"), key.expose()),
        UciBatchCommand::commit(FILE),
    ]
}

/// The key store's file: where uci keeps it.
fn path() -> PathBuf {
    PathBuf::from(env::uci_config_dir().unwrap_or_else(|| "/etc/config".to_owned())).join(FILE)
}

/// Only root may read or write the key store, the way OpenWrt keeps its own
/// files that hold secrets (`network`, `dhcp`, `dropbear`). `uci commit` keeps
/// the mode.
const KEY_STORE_MODE: u32 = 0o600;

/// Makes sure the key store's file at `path` exists and only its owner can read
/// or write it. Called before every write to the store, so a new file is private
/// before a secret goes in, and one an older splot left readable is tightened.
fn make_private(path: &Path) -> Result<(), KeyStoreError> {
    fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .and_then(|file| file.set_permissions(fs::Permissions::from_mode(KEY_STORE_MODE)))
        .map_err(|cause| write_error(cause.into()))
}

/// The key store couldn't be read: uci failed, or printed what isn't uci config.
fn read_error(cause: Box<dyn std::error::Error + Send + Sync>) -> KeyStoreError {
    KeyStoreError::Read {
        at: path().display().to_string(),
        cause,
    }
}

/// The key store couldn't be written, or made private.
fn write_error(cause: Box<dyn std::error::Error + Send + Sync>) -> KeyStoreError {
    KeyStoreError::Write {
        at: path().display().to_string(),
        cause,
    }
}

/// The node's key store on OpenWrt, the uci file `splot`: its private key
/// (`splot.config.private_key`), and the preshared key of each of its pairs
/// that has one (a `psk` section per peer).
pub struct UciKeyStore {
    private_key: WgPrivateKey,
    /// By section name (`psk_section`).
    psks: BTreeMap<String, WgPresharedKey>,
}

impl KeyStore for UciKeyStore {
    fn load() -> Result<Self, KeyStoreError> {
        let private_key = match uci::get(PRIVATE_KEY).map_err(|err| read_error(err.into()))? {
            Some(key) => key
                .parse()
                .map_err(|cause| KeyStoreError::InvalidPrivateKey {
                    at: PRIVATE_KEY.to_owned(),
                    cause,
                })?,
            None => return Err(KeyStoreError::NotInitialised),
        };

        let psks = match uci::export(FILE).map_err(|err| read_error(err.into()))? {
            Some(text) => psks(&export::parse(&text).map_err(|err| read_error(err.into()))?)?,
            None => BTreeMap::new(),
        };

        Ok(Self { private_key, psks })
    }

    fn create_private_key() -> Result<(), KeyStoreError> {
        make_private(&path())?;

        let private_key = wg::generate_private_key()?;
        uci::batch(&[
            UciBatchCommand::set("splot.config", "splot"),
            UciBatchCommand::set(PRIVATE_KEY, private_key.expose()),
            UciBatchCommand::commit("splot"),
        ])
        .map_err(|err| write_error(err.into()))
    }

    fn store_psk(peer: &HostRef, key: &WgPresharedKey) -> Result<(), KeyStoreError> {
        make_private(&path())?;
        uci::batch(&store_psk_commands(peer, key)).map_err(|err| write_error(err.into()))
    }

    fn private_key(&self) -> &WgPrivateKey {
        &self.private_key
    }

    fn psk(&self, peer: &HostRef) -> Option<&WgPresharedKey> {
        self.psks.get(&psk_section(peer).to_string())
    }
}

#[cfg(test)]
impl UciKeyStore {
    /// Test-only constructor bypassing uci — fields are private so that a real
    /// `UciKeyStore` can only come from `load()`, which validates the keys.
    pub(crate) fn for_tests(private_key: &str) -> Self {
        Self {
            private_key: private_key.parse().expect("a test's private key is a key"),
            psks: BTreeMap::new(),
        }
    }

    pub(crate) fn with_psk(mut self, peer: &HostRef, key: &str) -> Self {
        let key = key.parse().expect("a test's preshared key is a key");
        self.psks.insert(psk_section(peer).to_string(), key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, mode};

    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
    const CAMERA_PSK: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=";

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn lte_cam() -> HostRef {
        HostRef::Local {
            node: "Home".parse().unwrap(),
            name: "lte-cam".parse().unwrap(),
        }
    }

    fn store(text: &str) -> Result<UciKeyStore, KeyStoreError> {
        Ok(UciKeyStore {
            private_key: CABIN_PSK.parse().unwrap(),
            psks: psks(&export::parse(text).unwrap())?,
        })
    }

    #[test]
    fn the_key_store_is_created_readable_by_its_owner_only() {
        let dir = TempDir::new("store-created");
        let path = dir.0.join(FILE);

        make_private(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn an_existing_key_store_others_can_read_is_tightened() {
        let dir = TempDir::new("store-tightened");
        let path = dir.0.join(FILE);
        fs::write(&path, "package splot\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        make_private(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        // What it held stays.
        assert_eq!(fs::read_to_string(&path).unwrap(), "package splot\n");
    }

    #[test]
    fn a_psk_is_stored_in_a_section_named_like_its_peer() {
        let commands: Vec<String> = store_psk_commands(&lte_cam(), &CAMERA_PSK.parse().unwrap())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            commands,
            [
                "set splot.spl_psk_lte_cam='psk'",
                &format!("set splot.spl_psk_lte_cam.key='{CAMERA_PSK}'"),
                "commit splot",
            ]
        );
    }

    #[test]
    fn the_store_finds_each_pairs_psk_by_its_peer() {
        let store = store(&format!(
            "package splot

config splot 'config'
\toption private_key 'FAKE_MESH_KEY'

config psk 'spl_psk_Cabin'
\toption key '{CABIN_PSK}'

config psk 'spl_psk_lte_cam'
\toption key '{CAMERA_PSK}'

config psk 'spl_psk_Phone'

config other 'spl_psk_Lake'
\toption key '{CABIN_PSK}'
"
        ))
        .unwrap();

        let psk = |peer: &HostRef| store.psk(peer).map(WgPresharedKey::expose);
        assert_eq!(psk(&cabin()), Some(CABIN_PSK));
        assert_eq!(psk(&lte_cam()), Some(CAMERA_PSK));
        // A section without a key holds none, and neither does a section of
        // another type.
        assert_eq!(psk(&HostRef::Client("Phone".parse().unwrap())), None);
        assert_eq!(psk(&HostRef::Node("Lake".parse().unwrap())), None);
    }

    #[test]
    fn a_stored_psk_must_be_a_key() {
        let err = store(
            "package splot

config psk 'spl_psk_Cabin'
\toption key 'not a key'
",
        )
        .err()
        .unwrap();
        assert!(
            matches!(&err, KeyStoreError::InvalidPsk { at, .. } if at == "splot.spl_psk_Cabin"),
            "{err}"
        );
    }
}
