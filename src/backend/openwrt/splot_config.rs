use std::{collections::BTreeMap, fs, path::PathBuf};

use super::{
    export::{self, ParseError},
    naming::UciSectionName,
    section::{Section, Value},
    uci::{self, UciBatchCommand},
};
use crate::{
    env,
    model::host::HostRef,
    types::wg_key::{KeyFormatError, check_key_format},
    wg::{self, validate_private_key},
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
fn psks(sections: &[Section]) -> Result<BTreeMap<String, String>, SplotConfigError> {
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
            check_key_format(key).map_err(|cause| SplotConfigError::InvalidPsk {
                section: section.name.clone(),
                cause,
            })?;
            psks.insert(section.name.clone(), key.clone());
        }
    }

    Ok(psks)
}

/// The commands that store `key` as the preshared key of the node's pair with
/// `peer`, in place of any it had.
fn store_psk_commands(peer: &HostRef, key: &str) -> Vec<UciBatchCommand> {
    let section = psk_section(peer);

    vec![
        UciBatchCommand::set(format!("{FILE}.{section}"), PSK_TYPE),
        UciBatchCommand::set(format!("{FILE}.{section}.{PSK_KEY}"), key),
        UciBatchCommand::commit(FILE),
    ]
}

fn get_config_dir() -> PathBuf {
    PathBuf::from(env::uci_config_dir().unwrap_or_else(|| "/etc/config".to_owned()))
}

fn init_mesh_key() -> Result<String, SplotConfigError> {
    let path = get_config_dir().join("splot");
    fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)?;

    let private_key = wg::generate_private_key()?;
    uci::batch(&[
        UciBatchCommand::set("splot.config", "splot"),
        UciBatchCommand::set("splot.config.private_key", &private_key),
        UciBatchCommand::commit("splot"),
    ])?;

    Ok(private_key)
}

#[derive(Debug, thiserror::Error)]
pub enum SplotConfigError {
    #[error("failed to create splot config file")]
    Io(#[from] std::io::Error),
    #[error("stored mesh private key is invalid")]
    InvalidMeshKey(#[source] KeyFormatError),
    #[error("the preshared key stored in {FILE}.{section} is invalid")]
    InvalidPsk {
        section: String,
        #[source]
        cause: KeyFormatError,
    },
    #[error("that's not a preshared key (as `wg genpsk` prints one)")]
    NotAPsk(#[source] KeyFormatError),
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
    mesh_key: String,
    /// By section name (`psk_section`).
    psks: BTreeMap<String, String>,
}

impl SplotConfig {
    pub fn load() -> Result<Self, SplotConfigError> {
        let mesh_key = match uci::get("splot.config.private_key")? {
            Some(pk) => {
                validate_private_key(&pk).map_err(SplotConfigError::InvalidMeshKey)?;
                pk
            }

            None => init_mesh_key()?,
        };

        let psks = match uci::export(FILE)? {
            Some(text) => psks(&export::parse(&text).map_err(SplotConfigError::Export)?)?,
            None => BTreeMap::new(),
        };

        Ok(Self { mesh_key, psks })
    }

    pub fn mesh_key(&self) -> &str {
        &self.mesh_key
    }

    /// The preshared key of the node's pair with `peer`, if one is stored.
    pub fn psk(&self, peer: &HostRef) -> Option<&str> {
        self.psks
            .get(&psk_section(peer).to_string())
            .map(String::as_str)
    }

    /// Stores `key` as the preshared key of the node's pair with `peer`, in place
    /// of any it had, once it's checked to be one.
    pub fn store_psk(peer: &HostRef, key: &str) -> Result<(), SplotConfigError> {
        check_key_format(key).map_err(SplotConfigError::NotAPsk)?;
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
            mesh_key: mesh_key.to_owned(),
            psks: BTreeMap::new(),
        }
    }

    pub(crate) fn with_psk(mut self, peer: &HostRef, key: &str) -> Self {
        self.psks
            .insert(psk_section(peer).to_string(), key.to_owned());
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
            mesh_key: "FAKE_MESH_KEY".to_owned(),
            psks: psks(&export::parse(text).unwrap())?,
        })
    }

    #[test]
    fn a_psk_is_stored_in_a_section_named_like_its_peer() {
        let commands: Vec<String> = store_psk_commands(&lte_cam(), CAMERA_PSK)
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

        assert_eq!(store.psk(&cabin()), Some(CABIN_PSK));
        assert_eq!(store.psk(&lte_cam()), Some(CAMERA_PSK));
        // A section without a key holds none, and neither does a section of
        // another type.
        assert_eq!(store.psk(&HostRef::Client("Phone".parse().unwrap())), None);
        assert_eq!(store.psk(&HostRef::Node("Lake".parse().unwrap())), None);
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
