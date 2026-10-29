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
    /// What splot decides in the node's firewall: what its deny drops unless a
    /// service grants it, and the node's input from the mesh zone. None where
    /// splot leaves the firewall alone. The dry run warns about the operator's
    /// own sections that decide some of it too.
    pub owned: Vec<Crossing>,
}

/// Traffic from one zone to where it goes, as fw4 names the zones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crossing {
    pub from: String,
    pub to: Dest,
}

/// Where traffic from a zone goes: into a zone, into any zone, or to the node
/// itself (its input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dest {
    Zone(String),
    AnyZone,
    Node,
}

impl Rendered {
    /// The uci files it writes.
    pub fn files(&self) -> Vec<&str> {
        self.files.iter().map(|(file, _)| file.as_str()).collect()
    }
}
