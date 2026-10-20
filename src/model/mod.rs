//! The checked model: what a config becomes once it passed validation.

pub mod host;
pub mod node;
pub mod service;
pub mod validator;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    num::NonZeroU16,
};

use crate::{
    config::Config,
    types::{
        config_location::{ClientLoc, ConfigLocation, HubClientLoc, HubLoc, NodeLoc},
        identifier::Identifier,
        ip::Ipv4Network,
        wg_key::WgPublicKey,
    },
};
use host::{Host, HostAddress, HostRef, Place};
use node::Node;
use service::Service;
use validator::{
    Checked,
    types::{ValidationReport, ValidationWarning},
};

/// The network a config describes, once it passed validation. Only [`validate`]
/// makes one, so everything that reads it can rely on what validation checked.
pub struct Network {
    /// The whole mesh address space.
    mesh_network: Ipv4Network,
    nodes: BTreeMap<Identifier, Node>,
    hosts: Vec<Host>,
    services: BTreeMap<HostRef, BTreeMap<Identifier, Service>>,
    keepalive_interval: Option<NonZeroU16>,
}

impl Network {
    /// Every node, by name.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn node(&self, name: &Identifier) -> Option<&Node> {
        self.nodes.get(name)
    }

    /// Every host, in config order: each node, its devices zone by zone and its hub
    /// clients, then the global clients.
    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }

    /// Where the config has `key`: a node's, a hub client's or a global client's
    /// `publicKey`. Keys are unique, so there's at most one.
    pub fn key_location(&self, key: &WgPublicKey) -> Option<ConfigLocation> {
        if let Some(node) = self.nodes().find(|node| node.public_key() == key) {
            return Some(ConfigLocation::Node(
                node.name().clone(),
                NodeLoc::PublicKey,
            ));
        }

        let host = self.hosts.iter().find(|host| {
            host.wg_peer()
                .is_some_and(|wg_peer| wg_peer.public_key() == key)
        })?;

        Some(match host.id() {
            HostRef::Node(name) => ConfigLocation::Node(name.clone(), NodeLoc::PublicKey),
            HostRef::Local { node, name } => ConfigLocation::Node(
                node.clone(),
                NodeLoc::Hub(HubLoc::Client(name.clone(), HubClientLoc::PublicKey)),
            ),
            HostRef::Client(name) => ConfigLocation::Client(name.clone(), ClientLoc::PublicKey),
        })
    }

    /// The lowest address in the mesh network that nothing has: no node's or
    /// global client's mesh IP, in no hub network, and not the network's own or
    /// broadcast address. A suggestion for a new node; none when the mesh is full.
    pub fn free_mesh_ip(&self) -> Option<Ipv4Addr> {
        let taken: BTreeSet<Ipv4Addr> = self
            .hosts
            .iter()
            .flat_map(Host::addresses)
            .filter(|address| *address.place() == Place::Mesh)
            .map(HostAddress::ip)
            .collect();
        let hubs: Vec<Ipv4Network> = self.nodes().filter_map(|node| node.hub).collect();
        let mesh = self.mesh_network;

        (mesh.ip().to_bits()..=mesh.broadcast().to_bits())
            .map(Ipv4Addr::from_bits)
            .find(|ip| {
                mesh.host_interface(*ip).is_ok()
                    && !taken.contains(ip)
                    && !hubs.iter().any(|hub| hub.contains(*ip))
            })
    }

    /// Seconds between the keepalives splot turns on by itself; none when the
    /// config turns them off.
    pub fn keepalive_interval(&self) -> Option<NonZeroU16> {
        self.keepalive_interval
    }

    /// The services `host` offers, by name.
    pub fn services_of(&self, host: &Host) -> impl Iterator<Item = (&Identifier, &Service)> {
        self.services.get(host.id()).into_iter().flatten()
    }
}

/// A network, and the warnings its config produced.
pub struct Validated {
    pub network: Network,
    pub warnings: Vec<ValidationWarning>,
}

/// Turns `config` into a [`Network`] if it has no errors. Every problem is
/// reported, not just the first.
pub fn validate(config: &Config) -> Result<Validated, ValidationReport> {
    let Checked {
        nodes,
        hosts,
        services,
        report,
    } = validator::check(config);

    if report.errors.is_empty() {
        Ok(Validated {
            network: Network {
                mesh_network: config.mesh_network,
                nodes,
                hosts,
                services,
                keepalive_interval: NonZeroU16::new(config.keepalive_interval),
            },
            warnings: report.warnings,
        })
    } else {
        Err(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::host::{Host, HostAddress, HostRef, Place},
        test_support::{checked, config},
        types::identifier::Identifier,
    };

    // Home declares a WAN zone no service uses: a warning, not an error.
    const WARNING_ONLY: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
";

    #[test]
    fn config_with_warnings_only_becomes_a_network() {
        let Ok(validated) = validate(&config(WARNING_ONLY)) else {
            panic!("a config with warnings only must validate");
        };
        assert_eq!(validated.warnings.len(), 1);
    }

    #[test]
    fn config_with_errors_becomes_no_network() {
        // The same, plus a meshIp outside meshNetwork.
        let yaml = WARNING_ONLY.replace("meshIp: 10.100.0.1", "meshIp: 10.200.0.1");
        let Err(report) = validate(&config(&yaml)) else {
            panic!("a config with errors must not validate");
        };
        assert!(!report.errors.is_empty());
        // The warnings are still reported alongside the errors.
        assert_eq!(report.warnings.len(), 1);
    }

    // One host of every kind. The device (printer) sorts after the hub client
    // (camera) by name, but comes first in the config.
    const HOSTS: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:01
            services:
              ipp: { port: 631, proto: tcp, allowFrom: Phone }
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home: { lan: 192.168.1.60 }
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn local(node: &str, name: &str) -> HostRef {
        HostRef::Local {
            node: id(node),
            name: id(name),
        }
    }

    fn address(interface: &str, place: Place) -> HostAddress {
        HostAddress {
            interface: interface.parse().unwrap(),
            place,
        }
    }

    fn home_lan() -> Place {
        Place::Zone {
            node: id("Home"),
            zone: id("lan"),
        }
    }

    #[test]
    fn hosts_come_in_config_order() {
        let network = checked(HOSTS);
        let ids: Vec<HostRef> = network.hosts().iter().map(|h| h.id().clone()).collect();
        assert_eq!(
            ids,
            [
                HostRef::Node(id("Cabin")),
                HostRef::Node(id("Home")),
                local("Home", "printer"),
                local("Home", "camera"),
                HostRef::Client(id("Phone")),
            ]
        );
    }

    #[test]
    fn every_address_has_its_subnet_and_its_place() {
        let network = checked(HOSTS);
        let [_, home, printer, camera, phone] = network.hosts() else {
            panic!("expected five hosts");
        };

        assert_eq!(
            home.addresses(),
            [
                address("10.100.0.1/16", Place::Mesh),
                address("192.168.1.1/24", home_lan()),
            ]
        );
        assert_eq!(
            printer.addresses(),
            [address("192.168.1.50/24", home_lan())]
        );
        assert_eq!(
            camera.addresses(),
            [address("10.100.49.10/24", Place::Hub { node: id("Home") })]
        );
        assert_eq!(
            phone.addresses(),
            [
                address("10.100.1.10/16", Place::Mesh),
                address("192.168.1.60/24", home_lan()),
            ]
        );
    }

    #[test]
    fn a_node_carries_what_the_mesh_needs_of_it() {
        let network = checked(HOSTS);
        let home = network.node(&id("Home")).unwrap();

        assert_eq!(home.name().as_ref(), "Home");
        assert_eq!(
            home.public_key().as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(home.endpoint().unwrap().to_string(), "1.2.3.4");
        assert_eq!(home.listen_port().to_string(), "51820");
        // Its mesh IP with the mesh network's prefix.
        assert_eq!(home.mesh_address().to_string(), "10.100.0.1/16");
        assert_eq!(
            home.networks().map(|n| n.to_string()).collect::<Vec<_>>(),
            ["192.168.1.0/24", "10.100.49.0/24"]
        );

        let cabin = network.node(&id("Cabin")).unwrap();
        assert_eq!(cabin.networks().count(), 0);
        assert!(network.node(&id("Phone")).is_none());
    }

    #[test]
    fn nodes_and_clients_with_a_key_say_whether_they_use_psks() {
        let psks = |yaml: &str| {
            let network = checked(yaml);
            let [_, _, _, camera, phone] = network.hosts() else {
                panic!("expected five hosts");
            };
            let psk = |host: &Host| host.wg_peer().unwrap().psk();
            [
                network.node(&id("Home")).unwrap().psk(),
                network.node(&id("Cabin")).unwrap().psk(),
                psk(camera),
                psk(phone),
            ]
        };
        assert_eq!(psks(HOSTS), [true; 4]);

        let off = HOSTS
            .replace(
                "    endpoint: 5.6.7.8\n",
                "    endpoint: 5.6.7.8\n    psk: false\n",
            )
            .replace(
                "          ip: 10.100.49.10\n",
                "          ip: 10.100.49.10\n          psk: false\n",
            )
            .replace(
                "    meshIp: 10.100.1.10\n",
                "    meshIp: 10.100.1.10\n    psk: false\n",
            );
        assert_eq!(psks(&off), [true, false, false, false]);
    }

    #[test]
    fn hub_and_global_clients_carry_their_public_keys() {
        let network = checked(HOSTS);
        let [cabin, _, printer, camera, phone] = network.hosts() else {
            panic!("expected five hosts");
        };
        let key = |host: &Host| {
            host.wg_peer()
                .map(|wg_peer| wg_peer.public_key().as_str().to_owned())
        };

        assert_eq!(
            key(camera).unwrap(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
        );
        assert_eq!(
            key(phone).unwrap(),
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA="
        );
        // A node's key is on its node; a device has none.
        assert!(key(cabin).is_none());
        assert!(key(printer).is_none());
    }

    #[test]
    fn a_key_is_found_where_the_config_has_it() {
        let network = checked(HOSTS);
        let location = |key: &str| {
            network
                .key_location(&key.parse().unwrap())
                .map(|at| at.to_string())
        };

        assert_eq!(
            location("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=").as_deref(),
            Some("nodes.Cabin.publicKey")
        );
        assert_eq!(
            location("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=").as_deref(),
            Some("nodes.Home.hub.clients.camera.publicKey")
        );
        assert_eq!(
            location("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=").as_deref(),
            Some("clients.Phone.publicKey")
        );
        assert_eq!(
            location("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZA="),
            None
        );
    }

    #[test]
    fn a_new_node_is_offered_the_lowest_free_mesh_ip() {
        // .0 is the network's own address, .1 and .3 are nodes, .2 a global
        // client, .4-.7 Home's hub: .8 is the first that's free.
        let network = checked(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: 10.100.0.4/30
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.3
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.0.2
",
        );
        assert_eq!(network.free_mesh_ip(), Some("10.100.0.8".parse().unwrap()));
    }

    #[test]
    fn a_full_mesh_offers_no_mesh_ip() {
        // A /30 has two host addresses, both taken; nor is the broadcast free.
        let network = checked(
            "
meshNetwork: 10.100.0.0/30
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        assert_eq!(network.free_mesh_ip(), None);
    }

    #[test]
    fn a_keepalive_interval_of_0_turns_none_on() {
        let interval = |yaml: &str| checked(yaml).keepalive_interval().map(NonZeroU16::get);
        assert_eq!(
            interval(&format!("keepaliveInterval: 40\n{HOSTS}")),
            Some(40)
        );
        assert_eq!(interval(&format!("keepaliveInterval: 0\n{HOSTS}")), None);
    }

    #[test]
    fn a_host_carries_its_macs_and_the_network_its_services() {
        let network = checked(HOSTS);
        let [_, home, printer, camera, phone] = network.hosts() else {
            panic!("expected five hosts");
        };

        let services = |host| -> Vec<String> {
            network
                .services_of(host)
                .map(|(name, _)| name.to_string())
                .collect()
        };
        assert_eq!(services(printer), ["ipp"]);
        assert!(services(camera).is_empty());

        assert_eq!(printer.macs().len(), 1);
        assert_eq!(phone.macs().len(), 1);
        // Nodes and hub clients get no leases.
        assert!(home.macs().is_empty());
        assert!(camera.macs().is_empty());
    }
}
