use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use super::{
    export::{self, ParseError},
    naming::UciSectionName,
    section::{Section, Value},
    uci::{self, UciBatchCommand},
};
use crate::{
    env,
    model::host::HostRef,
    types::wg_key::{KeyFormatError, WgPresharedKey, WgPrivateKey},
    wg,
};

/// The uci file that holds the node's secrets.
const FILE: &str = "splot";
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
fn psks(sections: &[Section]) -> Result<BTreeMap<String, WgPresharedKey>, SplotConfigError> {
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
            let key = key.parse().map_err(|cause| SplotConfigError::InvalidPsk {
                section: section.name.clone(),
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

fn get_config_dir() -> PathBuf {
    PathBuf::from(env::uci_config_dir().unwrap_or_else(|| "/etc/config".to_owned()))
}

/// Only root may read or write the key store, the way OpenWrt keeps its own
/// files that hold secrets (`network`, `dhcp`, `dropbear`). `uci commit` keeps
/// the mode.
const KEY_STORE_MODE: u32 = 0o600;

/// Makes sure the key store's file at `path` exists and only its owner can read
/// or write it. Called before every write to the store, so a new file is private
/// before a secret goes in, and one an older splot left readable is tightened.
fn make_private(path: &Path) -> Result<(), SplotConfigError> {
    let file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(KEY_STORE_MODE))?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SplotConfigError {
    #[error("this peer has no WireGuard key yet - run `splot init --node <name>` first")]
    NotInitialised,
    #[error("can't create the key store or make it private")]
    Io(#[from] std::io::Error),
    #[error("stored mesh private key is invalid")]
    InvalidMeshKey(#[source] KeyFormatError),
    #[error("the preshared key stored in {FILE}.{section} is invalid")]
    InvalidPsk {
        section: String,
        #[source]
        cause: KeyFormatError,
    },
    #[error("can't read the key store ({FILE})")]
    Export(#[source] ParseError),
    #[error("uci error")]
    Uci(#[from] uci::Error),
    #[error("failed to generate a WireGuard key")]
    Wg(#[from] wg::Error),
}

/// The node's key store: its private key, and the preshared key of each of its
/// pairs that has one.
pub struct SplotConfig {
    mesh_key: WgPrivateKey,
    /// By section name (`psk_section`).
    psks: BTreeMap<String, WgPresharedKey>,
}

impl SplotConfig {
    /// The peer's key store. Writes nothing: a peer without a key is told to
    /// run `splot init`.
    pub fn load() -> Result<Self, SplotConfigError> {
        let mesh_key = match uci::get("splot.config.private_key")? {
            Some(key) => key.parse().map_err(SplotConfigError::InvalidMeshKey)?,
            None => return Err(SplotConfigError::NotInitialised),
        };

        let psks = match uci::export(FILE)? {
            Some(text) => psks(&export::parse(&text).map_err(SplotConfigError::Export)?)?,
            None => BTreeMap::new(),
        };

        Ok(Self { mesh_key, psks })
    }

    pub fn mesh_key(&self) -> &WgPrivateKey {
        &self.mesh_key
    }

    /// Generates the peer's private key and stores it. Only `splot init` does,
    /// and only when the peer has none: a key is never replaced.
    pub fn create_private_key() -> Result<(), SplotConfigError> {
        make_private(&get_config_dir().join(FILE))?;

        let private_key = wg::generate_private_key()?;
        uci::batch(&[
            UciBatchCommand::set("splot.config", "splot"),
            UciBatchCommand::set("splot.config.private_key", private_key.expose()),
            UciBatchCommand::commit("splot"),
        ])?;

        Ok(())
    }

    /// The preshared key of the node's pair with `peer`, if one is stored.
    pub fn psk(&self, peer: &HostRef) -> Option<&WgPresharedKey> {
        self.psks.get(&psk_section(peer).to_string())
    }

    /// Stores `key` as the preshared key of the node's pair with `peer`, in place
    /// of any it had.
    pub fn store_psk(peer: &HostRef, key: &WgPresharedKey) -> Result<(), SplotConfigError> {
        make_private(&get_config_dir().join(FILE))?;
        uci::batch(&store_psk_commands(peer, key))?;

        Ok(())
    }
}

#[cfg(test)]
impl SplotConfig {
    /// Test-only constructor bypassing uci — fields are private so that a real
    /// `SplotConfig` can only come from `load()`, which validates the keys.
    pub(crate) fn for_tests(mesh_key: &str) -> Self {
        Self {
            mesh_key: mesh_key.parse().expect("a test's private key is a key"),
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

    fn store(text: &str) -> Result<SplotConfig, SplotConfigError> {
        Ok(SplotConfig {
            mesh_key: CABIN_PSK.parse().unwrap(),
            psks: psks(&export::parse(text).unwrap())?,
        })
    }

    /// A directory of its own under the system's temp dir, gone when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("splot-{name}-{}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
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
            matches!(&err, SplotConfigError::InvalidPsk { section, .. } if section == "spl_psk_Cabin"),
            "{err}"
        );
    }
}
