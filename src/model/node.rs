//! Nodes: the mesh's routers.

use std::collections::BTreeMap;

use super::platform::Platform;
use crate::types::{
    endpoint::EndpointHost,
    identifier::Identifier,
    ip::{Ipv4Interface, Ipv4Network},
    port::Port,
    wg_key::WgPublicKey,
};

/// One of the mesh's routers, as the other nodes and its own config see it.
#[derive(Debug)]
pub struct Node {
    pub(super) name: Identifier,
    pub(super) platform: Platform,
    pub(super) public_key: WgPublicKey,
    /// Where the other nodes dial it; none when nobody can.
    pub(super) endpoint: Option<EndpointHost>,
    pub(super) listen_port: Port,
    /// Whether its pairs use a preshared key (when the other end wants one too).
    pub(super) psk: bool,
    /// Its mesh IP with the mesh network's prefix: the address of its mesh
    /// interface.
    pub(super) mesh_address: Ipv4Interface,
    /// Its zones' subnets, by zone name.
    pub(super) zones: BTreeMap<Identifier, Ipv4Network>,
    pub(super) hub: Option<Ipv4Network>,
    /// The firewall zone it reaches the internet through, if it exposes services.
    pub(super) wan_zone: Option<Identifier>,
}

impl Node {
    pub fn name(&self) -> &Identifier {
        &self.name
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn public_key(&self) -> &WgPublicKey {
        &self.public_key
    }

    pub fn endpoint(&self) -> Option<&EndpointHost> {
        self.endpoint.as_ref()
    }

    pub fn listen_port(&self) -> Port {
        self.listen_port
    }

    pub fn psk(&self) -> bool {
        self.psk
    }

    pub fn mesh_address(&self) -> Ipv4Interface {
        self.mesh_address
    }

    /// What sits behind it: its zones and its hub. Other nodes route these
    /// through it, the hub even while it has no clients.
    pub fn networks(&self) -> impl Iterator<Item = Ipv4Network> {
        self.zones.values().copied().chain(self.hub)
    }

    pub fn wan_zone(&self) -> Option<&Identifier> {
        self.wan_zone.as_ref()
    }
}
