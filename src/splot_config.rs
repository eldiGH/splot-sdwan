use std::{collections::HashMap, fs, iter, path::PathBuf};

use crate::{
    env,
    types::identifier::Identifier,
    types::wg_key::KeyFormatError,
    uci::{self, UciBatchCommand},
    wg::{self, validate_private_key},
};

fn get_config_dir() -> PathBuf {
    PathBuf::from(env::uci_config_dir().unwrap_or_else(|| "/etc/config".to_owned()))
}

/// uci option holding a VPN interface's private key. Option names follow the same
/// rules as section names, so `-` in the interface name is mapped to `_`.
fn vpn_key_path(interface: &Identifier) -> String {
    format!("splot.vpn_interface_keys.{}", uci::name(interface.as_ref()))
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
    #[error("stored vpn interface private key is invalid")]
    InvalidVpnInterfaceKey {
        #[source]
        err: KeyFormatError,
        interface: Identifier,
    },
    #[error("uci error")]
    Uci(#[from] uci::Error),
    #[error("failed to generate a WireGuard key")]
    Wg(#[from] wg::Error),
}

pub struct SplotConfig {
    mesh_key: String,
    vpn_interface_keys: HashMap<Identifier, String>,
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

        Ok(Self {
            mesh_key,
            vpn_interface_keys: HashMap::new(),
        })
    }

    pub fn ensure_vpn_keys<'a>(
        &mut self,
        interfaces: impl Iterator<Item = &'a Identifier>,
    ) -> Result<(), SplotConfigError> {
        let mut keys_to_add = HashMap::new();

        for interface in interfaces {
            match uci::get(&vpn_key_path(interface))? {
                Some(key) => {
                    validate_private_key(&key).map_err(|err| {
                        SplotConfigError::InvalidVpnInterfaceKey {
                            err,
                            interface: interface.clone(),
                        }
                    })?;
                    self.vpn_interface_keys.insert(interface.clone(), key);
                }

                None => {
                    let key = wg::generate_private_key()?;
                    keys_to_add.insert(interface.clone(), key.clone());
                    self.vpn_interface_keys.insert(interface.clone(), key);
                }
            }
        }

        if keys_to_add.is_empty() {
            return Ok(());
        }

        let commands = iter::once(UciBatchCommand::set("splot.vpn_interface_keys", "keys"))
            .chain(
                keys_to_add
                    .into_iter()
                    .map(|(interface, key)| UciBatchCommand::set(vpn_key_path(&interface), key)),
            )
            .chain(iter::once(UciBatchCommand::commit("splot")))
            .collect::<Vec<_>>();

        uci::batch(&commands)?;

        Ok(())
    }

    pub fn mesh_key(&self) -> &str {
        &self.mesh_key
    }

    pub fn vpn_interface_keys(&self) -> &HashMap<Identifier, String> {
        &self.vpn_interface_keys
    }
}

#[cfg(test)]
impl SplotConfig {
    /// Test-only constructor bypassing uci — fields are private so that a real
    /// `SplotConfig` can only come from `load()`, which validates the keys.
    pub(crate) fn for_tests(mesh_key: &str, vpn_interface_keys: &[(&str, &str)]) -> Self {
        Self {
            mesh_key: mesh_key.to_owned(),
            vpn_interface_keys: vpn_interface_keys
                .iter()
                .map(|(name, key)| (name.parse().unwrap(), (*key).to_owned()))
                .collect(),
        }
    }
}
