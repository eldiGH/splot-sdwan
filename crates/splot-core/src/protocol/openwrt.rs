//! The config of an OpenWrt node: uci sections, file by file.

use serde::{Deserialize, Serialize};

use crate::{
    identifier::Identifier,
    uci::{section::Section, slot::Slot},
    wg_key::WgPublicKey,
};

/// The node's config as uci sections, file by file, in the order they're
/// committed, with placeholders where its secrets go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rendered {
    /// The node it's for, and the key the config has for it: the agent checks
    /// it runs on that node before anything else.
    pub node: Identifier,
    pub public_key: WgPublicKey,
    /// Whether splot runs the node's WireGuard: then its key store has the key,
    /// and the secrets. Otherwise the node's own WireGuard has the key.
    pub wireguard: bool,
    pub files: Vec<(String, Vec<Section>)>,
    /// Where its secrets go: the agent fills them in from the key store.
    pub secrets: Vec<Slot>,
}

impl Rendered {
    /// The uci files it writes.
    pub fn files(&self) -> Vec<&str> {
        self.files.iter().map(|(file, _)| file.as_str()).collect()
    }
}
