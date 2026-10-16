use std::{fs, path::PathBuf};

use super::uci::{self, UciBatchCommand};
use crate::{
    env,
    types::wg_key::KeyFormatError,
    wg::{self, validate_private_key},
};

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
    #[error("uci error")]
    Uci(#[from] uci::Error),
    #[error("failed to generate a WireGuard key")]
    Wg(#[from] wg::Error),
}

pub struct SplotConfig {
    mesh_key: String,
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

        Ok(Self { mesh_key })
    }

    pub fn mesh_key(&self) -> &str {
        &self.mesh_key
    }
}

#[cfg(test)]
impl SplotConfig {
    /// Test-only constructor bypassing uci — fields are private so that a real
    /// `SplotConfig` can only come from `load()`, which validates the keys.
    pub(crate) fn for_tests(mesh_key: &str) -> Self {
        Self {
            mesh_key: mesh_key.to_owned(),
        }
    }
}
