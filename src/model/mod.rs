//! The checked model: what a config becomes once it passed validation.

pub mod host;
pub mod node;
pub mod service;
pub mod validator;

use std::{collections::BTreeMap, num::NonZeroU16};

use crate::{config::Config, types::identifier::Identifier};
use host::{Host, HostRef};
use node::Node;
use service::Service;
use validator::{
    Checked,
    types::{ValidationReport, ValidationWarning},
};

/// The network a config describes, once it passed validation. Only [`validate`]
/// makes one, so everything that reads it can rely on what validation checked.
pub struct Network {
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

    /// The node with this public key. Keys are unique, so there's at most one.
    pub fn find_node_by_public_key(&self, public_key: &str) -> Option<&Node> {
        self.nodes
            .values()
            .find(|node| node.public_key.as_str() == public_key)
    }

    /// Every host, in config order: each node, its devices zone by zone and its hub
    /// clients, then the global clients.
    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }

    /// Seconds between the keepalives splot turns on by itself; none when the
    /// config turns them off.
    pub fn keepalive_interval(&self) -> Option<NonZeroU16> {
        self.keepalive_interval
    }

    /// Whether the host offers any service.
    pub fn offers_services(&self, host: &HostRef) -> bool {
        self.services
            .get(host)
            .is_some_and(|services| !services.is_empty())
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
        assert_eq!(home.endpoint().to_string(), "1.2.3.4");
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
    fn a_node_is_found_by_its_public_key() {
        let network = checked(HOSTS);
        let found = network.find_node_by_public_key("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=");
        assert_eq!(
            found.map(|node| node.name().to_string()),
            Some("Cabin".into())
        );
        // A hub client's key is no node's.
        assert!(
            network
                .find_node_by_public_key("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
                .is_none()
        );
    }

    #[test]
    fn hub_and_global_clients_carry_their_public_keys() {
        let network = checked(HOSTS);
        let [cabin, _, printer, camera, phone] = network.hosts() else {
            panic!("expected five hosts");
        };
        let key = |host: &Host| host.public_key().map(|key| key.as_str().to_owned());

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
    fn a_host_offers_services_when_it_has_any() {
        let (network, home) = (checked(HOSTS), HostRef::Node(id("Home")));
        assert!(network.offers_services(&local("Home", "printer")));
        assert!(!network.offers_services(&home));
        assert!(!network.offers_services(&local("Home", "camera")));
        assert!(!network.offers_services(&HostRef::Client(id("Nobody"))));
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
