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
    pub files: Vec<File>,
    /// Where its secrets go: the agent fills them in from the key store.
    pub secrets: Vec<Slot>,
    /// What splot decides in the node's firewall: what its deny drops unless a
    /// service grants it, and the node's input from the mesh zone. None where
    /// splot leaves the firewall alone. The dry run warns about the operator's
    /// own sections that decide some of it too.
    pub owned: Vec<Crossing>,
    /// splot's values in the operator's dnsmasq sections; none where splot
    /// leaves the DNS alone.
    pub dnsmasq: Option<DnsmasqValues>,
}

/// One uci file splot writes: the sections it renders there, and the types of
/// splot's own sections it owns there. Two concerns share `dhcp`: each one
/// splot manages brings its types, and the old sections of one it leaves
/// alone stay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub name: String,
    pub types: Vec<String>,
    pub sections: Vec<Section>,
}

/// What splot puts into the operator's dnsmasq sections, where dnsmasq on
/// OpenWrt reads them and nowhere else: each section holds these values in
/// these options beside its own. splot owns every value that names a domain
/// inside `domains` (whoever added it), and those it recorded adding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsmasqValues {
    /// `server`: `/home.example.org/` (answered here alone),
    /// `/cabin.example.org/192.168.2.1` (forwarded), `/wg.cabin.example.org/#`
    /// (to public DNS).
    pub server: Vec<String>,
    /// `rebind_domain`: each forwarded domain, whose answers are private
    /// addresses.
    pub rebind_domain: Vec<String>,
    /// The mesh's domains.
    pub domains: Vec<String>,
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
        self.files.iter().map(|file| file.name.as_str()).collect()
    }
}
