//! Hosts: everything in the network that has an address.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use crate::{
    model::service::Service,
    types::{identifier::Identifier, ip::Ipv4Interface, mac::MacAddress},
};

/// Which host it is, by the name an `allowFrom` refers to it with. A zone device
/// and a hub client share their node's namespace (`Cabin.camera` either way), so
/// both are `Local`; which of the two it is shows in where its address lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostRef {
    Node(Identifier),
    Local { node: Identifier, name: Identifier },
    Client(Identifier),
}

impl HostRef {
    /// Its own name, without its node's.
    pub fn name(&self) -> &Identifier {
        match self {
            Self::Node(name) | Self::Local { name, .. } | Self::Client(name) => name,
        }
    }
}

/// Where an address lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    Zone {
        node: Identifier,
        zone: Identifier,
    },
    Hub {
        node: Identifier,
    },
    /// The mesh itself: a node's or a global client's mesh IP.
    Mesh,
}

impl Place {
    /// The node whose zone or hub it is. The mesh is no one node's.
    pub fn node(&self) -> Option<&Identifier> {
        match self {
            Self::Zone { node, .. } | Self::Hub { node } => Some(node),
            Self::Mesh => None,
        }
    }
}

/// One of a host's addresses: its IP with the prefix of the subnet it's on
/// (checked to be a host there), and where that subnet lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    pub(super) interface: Ipv4Interface,
    pub(super) place: Place,
}

impl HostAddress {
    pub fn ip(&self) -> Ipv4Addr {
        self.interface.ip()
    }

    pub fn place(&self) -> &Place {
        &self.place
    }

    /// Whether `ip` reaches this address directly rather than through a node, so
    /// no firewall sees the traffic. Only a zone is a shared link: on the mesh and
    /// on a hub every peer reaches the others through a node.
    pub fn shares_link(&self, ip: Ipv4Addr) -> bool {
        match self.place {
            Place::Zone { .. } => self.interface.is_in_same_network(ip),
            Place::Hub { .. } | Place::Mesh => self.interface.ip() == ip,
        }
    }
}

/// Anything with an address: a node, a zone device, a hub client or a global
/// client.
#[derive(Debug)]
pub struct Host {
    pub(super) id: HostRef,
    pub(super) addresses: Vec<HostAddress>,
    pub(super) macs: BTreeSet<MacAddress>,
    pub(super) services: BTreeMap<Identifier, Service>,
}

impl Host {
    pub fn id(&self) -> &HostRef {
        &self.id
    }

    /// A node's mesh IP and its address on each zone; a device's or a hub
    /// client's IP; a global client's mesh IP and its IP on each zone it's on.
    pub fn addresses(&self) -> &[HostAddress] {
        &self.addresses
    }

    /// Its addresses on the nodes `pick` chooses. An address is on a node when it's
    /// in the node's zone or hub, or when it's the node's own. A global client's
    /// mesh IP is on none: it's a peer on every node, so behind none of them in
    /// particular.
    pub fn addresses_on(
        &self,
        pick: impl Fn(&Identifier) -> bool,
    ) -> impl Iterator<Item = &HostAddress> {
        self.addresses
            .iter()
            .filter(move |address| self.node_of(address).is_some_and(&pick))
    }

    /// The node `address`, one of this host's own, is on.
    fn node_of<'a>(&'a self, address: &'a HostAddress) -> Option<&'a Identifier> {
        match &self.id {
            HostRef::Node(node) => Some(node),
            _ => address.place.node(),
        }
    }

    /// The MACs its DHCP leases are for. Only devices and global clients have
    /// them.
    pub fn macs(&self) -> &BTreeSet<MacAddress> {
        &self.macs
    }

    pub fn services(&self) -> &BTreeMap<Identifier, Service> {
        &self.services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(interface: &str, place: Place) -> HostAddress {
        HostAddress {
            interface: interface.parse().unwrap(),
            place,
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    #[test]
    fn a_zone_is_a_shared_link() {
        let printer = address(
            "192.168.1.50/24",
            Place::Zone {
                node: id("Home"),
                zone: id("lan"),
            },
        );
        assert!(printer.shares_link(ip("192.168.1.60")));
        assert!(!printer.shares_link(ip("192.168.2.60")));
    }

    #[test]
    fn hubs_and_the_mesh_share_no_link() {
        // Same subnet, but the traffic goes through a node.
        let camera = address("10.100.49.10/24", Place::Hub { node: id("Home") });
        assert!(!camera.shares_link(ip("10.100.49.11")));
        assert!(camera.shares_link(ip("10.100.49.10")));

        let phone = address("10.100.1.10/16", Place::Mesh);
        assert!(!phone.shares_link(ip("10.100.1.11")));
        assert!(phone.shares_link(ip("10.100.1.10")));
    }

    fn zone(node: &str, zone: &str) -> Place {
        Place::Zone {
            node: id(node),
            zone: id(zone),
        }
    }

    fn host(id: HostRef, addresses: Vec<HostAddress>) -> Host {
        Host {
            id,
            addresses,
            macs: BTreeSet::new(),
            services: BTreeMap::new(),
        }
    }

    /// The IPs of `host`'s addresses on the nodes `pick` chooses.
    fn ips_on(host: &Host, pick: impl Fn(&Identifier) -> bool) -> Vec<String> {
        host.addresses_on(pick)
            .map(|address| address.ip().to_string())
            .collect()
    }

    #[test]
    fn all_of_a_nodes_own_addresses_are_on_it() {
        // Its mesh IP too, though the mesh is no one node's.
        let home = host(
            HostRef::Node(id("Home")),
            vec![
                address("10.100.0.1/16", Place::Mesh),
                address("192.168.1.1/24", zone("Home", "lan")),
            ],
        );
        assert_eq!(
            ips_on(&home, |node| *node == id("Home")),
            ["10.100.0.1", "192.168.1.1"]
        );
        assert!(ips_on(&home, |node| *node != id("Home")).is_empty());
    }

    #[test]
    fn a_local_hosts_address_is_on_its_node() {
        let camera = host(
            HostRef::Local {
                node: id("Home"),
                name: id("camera"),
            },
            vec![address("10.100.49.10/24", Place::Hub { node: id("Home") })],
        );
        assert_eq!(
            ips_on(&camera, |node| *node == id("Home")),
            ["10.100.49.10"]
        );
        assert!(ips_on(&camera, |node| *node != id("Home")).is_empty());
    }

    #[test]
    fn a_global_clients_mesh_ip_is_on_no_node() {
        // A peer on every node, so behind none of them in particular.
        let phone = host(
            HostRef::Client(id("Phone")),
            vec![
                address("10.100.1.10/16", Place::Mesh),
                address("192.168.1.60/24", zone("Home", "lan")),
                address("192.168.2.60/24", zone("Cabin", "lan")),
            ],
        );
        assert_eq!(ips_on(&phone, |node| *node == id("Home")), ["192.168.1.60"]);
        assert_eq!(ips_on(&phone, |node| *node != id("Home")), ["192.168.2.60"]);
        assert_eq!(ips_on(&phone, |_| true), ["192.168.1.60", "192.168.2.60"]);
    }
}
