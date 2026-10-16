use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    iter,
};

use crate::{
    config::{self, Client, Config, Node},
    model::{
        host::Place,
        service::{Source, Sources},
        validator::types::{ValidationError, ValidationReport, ValidationWarning},
    },
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{ConfigLocation, ServiceLoc},
        identifier::Identifier,
        ip::Ipv4Network,
        schema_helpers::OneOrManyUnique,
    },
};

/// What each reference names, and where it lives.
#[derive(Default)]
pub(super) struct Resolution {
    /// Every reference but `$node`. A known reference with nothing behind it (a
    /// node with no zones and no hub) has no entry.
    sources: BTreeMap<AllowFromRef, BTreeSet<Source>>,
    /// What `$node` names on each node: its own address on each of its zones.
    this_node: BTreeMap<Identifier, BTreeSet<Source>>,
}

impl Resolution {
    pub(super) fn of(config: &Config) -> Self {
        let mut resolution = Self::default();

        for (node_name, node) in &config.nodes {
            resolution.add_node(node_name, node);
        }

        for (client_name, client) in &config.clients {
            resolution.add_client(client_name, client);
        }

        resolution
    }

    fn add(&mut self, references: impl IntoIterator<Item = AllowFromRef>, source: &Source) {
        for reference in references {
            self.sources
                .entry(reference)
                .or_default()
                .insert(source.clone());
        }
    }

    /// A bare node name and the node's tags name its zones and its hub: subnets,
    /// any device on them. `$node` is the router itself: its address on each zone.
    fn add_node(&mut self, node_name: &Identifier, node: &Node) {
        let node_refs: Vec<AllowFromRef> = iter::once(node_name.clone())
            .chain(node.tags.iter().cloned())
            .map(AllowFromRef::Bare)
            .collect();
        // Something inside the node: its qualified name and its tags.
        let local_refs = |name: &Identifier, tags: &OneOrManyUnique<Identifier>| {
            iter::once(AllowFromRef::nested(node_name.clone(), name.clone()))
                .chain(tags.iter().cloned().map(AllowFromRef::Bare))
                .collect::<Vec<_>>()
        };
        let mut this_node = BTreeSet::new();

        for (zone_name, zone) in &node.zones {
            let place = Place::Zone {
                node: node_name.clone(),
                zone: zone_name.clone(),
            };
            let subnet = Source {
                network: zone.address.network(),
                place: place.clone(),
            };

            self.add(node_refs.iter().cloned(), &subnet);
            self.add(local_refs(zone_name, &zone.tags), &subnet);

            this_node.insert(Source {
                network: Ipv4Network::host(zone.address.ip()),
                place: place.clone(),
            });

            for (device_name, device) in &zone.devices {
                let host = Source {
                    network: Ipv4Network::host(device.ip),
                    place: place.clone(),
                };
                self.add(local_refs(device_name, &device.tags), &host);
            }
        }

        self.this_node.insert(node_name.clone(), this_node);

        let Some(hub) = &node.hub else { return };
        let place = Place::Hub {
            node: node_name.clone(),
        };
        let network = Source {
            network: hub.network,
            place: place.clone(),
        };

        self.add(node_refs.iter().cloned(), &network);
        self.add(local_refs(&Identifier::hub(), &hub.tags), &network);

        for (client_name, client) in &hub.clients {
            let host = Source {
                network: Ipv4Network::host(client.ip),
                place: place.clone(),
            };
            self.add(local_refs(client_name, &client.tags), &host);
        }
    }

    /// A global client's name and tags name all its IPs: its mesh IP and its IP on
    /// each zone it's on.
    fn add_client(&mut self, client_name: &Identifier, client: &Client) {
        let refs = iter::once(client_name.clone())
            .chain(client.tags.iter().cloned())
            .map(AllowFromRef::Bare)
            .collect::<Vec<_>>();

        let mesh = client.mesh_ip.map(|mesh_ip| Source {
            network: Ipv4Network::host(mesh_ip),
            place: Place::Mesh,
        });
        let zones = client.ips.iter().flat_map(|(node_name, zones)| {
            zones.iter().map(|(zone_name, ip)| Source {
                network: Ipv4Network::host(*ip),
                place: Place::Zone {
                    node: node_name.clone(),
                    zone: zone_name.clone(),
                },
            })
        });

        for source in mesh.into_iter().chain(zones) {
            self.add(refs.iter().cloned(), &source);
        }
    }
}

/// Resolves the service's `allowFrom`. An unknown reference is reported and left
/// out.
pub(super) fn resolve_sources(
    service: &config::Service,
    known_references: &HashSet<AllowFromRef>,
    resolution: &Resolution,
    report: &mut ValidationReport,
    locate: impl Fn(ServiceLoc) -> ConfigLocation,
) -> Sources {
    let has_lan_access = !service.allow_from.is_empty();
    let has_wan_access = service.wan.as_ref().is_some_and(|wan| !wan.via.is_empty());

    if !has_lan_access && !has_wan_access {
        report.warnings.push(ValidationWarning::UnreachableService {
            at: locate(ServiceLoc::Root),
        });
    }

    let mut sources = Sources::default();

    for reference in &service.allow_from {
        if !known_references.contains(reference) {
            report.errors.push(ValidationError::UnknownRef {
                reference: reference.clone(),
                at: locate(ServiceLoc::AllowFrom),
            });
        } else if *reference == AllowFromRef::SelfNode {
            sources.this_node = resolution.this_node.clone();
        } else if let Some(found) = resolution.sources.get(reference) {
            sources.everywhere.extend(found.iter().cloned());
        }
    }

    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::host::HostRef,
        test_support::{checked, config},
    };

    // Home: zone lan (192.168.1.1/24) with device printer (192.168.1.50, tag printable)
    //       zone guest (192.168.2.1/24)
    //       hub 10.100.49.0/24 (tag cameras) with client doorcam (10.100.49.10, tag outdoor)
    //       node tags: server; service dns from $node and Phone
    // Cabin: zone lan (192.168.3.1/24)
    // Phone: meshIp 10.100.0.100, ips.Home.lan 192.168.1.60, ips.Cabin.lan 192.168.3.10, tag mobile
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    tags: server
    services:
      dns: { port: 53, proto: udp, allowFrom: [$node, Phone] }
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
            tags: printable
      guest:
        address: 192.168.2.1/24
    hub:
      network: 10.100.49.0/24
      tags: cameras
      clients:
        doorcam:
          publicKey: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA=
          ip: 10.100.49.10
          tags: outdoor
  Cabin:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.3.1/24
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.0.100
    macs: AA:BB:CC:DD:EE:01
    tags: mobile
    ips:
      Home:
        lan: 192.168.1.60
      Cabin:
        lan: 192.168.3.10
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn bare(s: &str) -> AllowFromRef {
        AllowFromRef::Bare(id(s))
    }

    fn nested(node: &str, local: &str) -> AllowFromRef {
        AllowFromRef::nested(id(node), id(local))
    }

    fn zone(node: &str, zone: &str) -> Place {
        Place::Zone {
            node: id(node),
            zone: id(zone),
        }
    }

    fn hub(node: &str) -> Place {
        Place::Hub { node: id(node) }
    }

    fn source(network: &str, place: Place) -> Source {
        Source {
            network: network.parse().unwrap(),
            place,
        }
    }

    fn resolution() -> Resolution {
        Resolution::of(&config(FIXTURE))
    }

    fn sources(reference: &AllowFromRef) -> BTreeSet<Source> {
        resolution()
            .sources
            .get(reference)
            .cloned()
            .unwrap_or_default()
    }

    // ── nodes: their zones' subnets and their hub ─────────────────────────

    #[test]
    fn node_name_yields_its_zone_subnets_and_hub() {
        assert_eq!(
            sources(&bare("Home")),
            BTreeSet::from([
                source("192.168.1.0/24", zone("Home", "lan")),
                source("192.168.2.0/24", zone("Home", "guest")),
                source("10.100.49.0/24", hub("Home")),
            ])
        );
    }

    #[test]
    fn node_tag_yields_the_same_as_its_name() {
        assert_eq!(sources(&bare("server")), sources(&bare("Home")));
    }

    // ── $node: the router's own address on each of its zones, per node ────

    #[test]
    fn this_node_is_the_routers_own_address_on_each_zone() {
        let resolution = resolution();
        assert_eq!(
            resolution.this_node[&id("Home")],
            BTreeSet::from([
                source("192.168.1.1/32", zone("Home", "lan")),
                source("192.168.2.1/32", zone("Home", "guest")),
            ])
        );
        assert_eq!(
            resolution.this_node[&id("Cabin")],
            BTreeSet::from([source("192.168.3.1/32", zone("Cabin", "lan"))])
        );
    }

    #[test]
    fn a_service_from_this_node_resolves_on_each_node() {
        let network = checked(FIXTURE);
        let sources = network.services[&HostRef::Node(id("Home"))][&id("dns")].sources();
        let on = |node: &str| -> Vec<String> {
            sources
                .on(&id(node))
                .map(|source| source.network().to_string())
                .collect()
        };

        // Phone's IPs, then the node's own.
        let phone = ["10.100.0.100/32", "192.168.1.60/32", "192.168.3.10/32"];
        assert_eq!(
            on("Home"),
            [&phone[..], &["192.168.1.1/32", "192.168.2.1/32"]].concat()
        );
        assert_eq!(on("Cabin"), [&phone[..], &["192.168.3.1/32"]].concat());
    }

    // ── a node's zones and devices ────────────────────────────────────────

    #[test]
    fn qualified_zone_yields_its_subnet() {
        assert_eq!(
            sources(&nested("Home", "lan")),
            BTreeSet::from([source("192.168.1.0/24", zone("Home", "lan"))])
        );
    }

    #[test]
    fn qualified_device_and_its_tag_yield_its_ip() {
        let printer = BTreeSet::from([source("192.168.1.50/32", zone("Home", "lan"))]);
        assert_eq!(sources(&nested("Home", "printer")), printer);
        assert_eq!(sources(&bare("printable")), printer);
    }

    // ── the hub and its clients ───────────────────────────────────────────

    #[test]
    fn hub_and_its_tag_yield_the_hub_network() {
        let network = BTreeSet::from([source("10.100.49.0/24", hub("Home"))]);
        assert_eq!(sources(&nested("Home", "hub")), network);
        assert_eq!(sources(&bare("cameras")), network);
    }

    #[test]
    fn hub_client_and_its_tag_yield_its_ip() {
        let doorcam = BTreeSet::from([source("10.100.49.10/32", hub("Home"))]);
        assert_eq!(sources(&nested("Home", "doorcam")), doorcam);
        assert_eq!(sources(&bare("outdoor")), doorcam);
    }

    // ── global clients: all their IPs ─────────────────────────────────────

    #[test]
    fn client_name_yields_its_mesh_ip_and_its_zone_ips() {
        assert_eq!(
            sources(&bare("Phone")),
            BTreeSet::from([
                source("10.100.0.100/32", Place::Mesh),
                source("192.168.1.60/32", zone("Home", "lan")),
                source("192.168.3.10/32", zone("Cabin", "lan")),
            ])
        );
    }

    #[test]
    fn client_tag_yields_the_same_as_its_name() {
        assert_eq!(sources(&bare("mobile")), sources(&bare("Phone")));
    }

    #[test]
    fn a_node_with_nothing_behind_it_has_no_sources() {
        let resolution = Resolution::of(&config(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
",
        ));
        assert!(!resolution.sources.contains_key(&bare("Home")));
        assert!(resolution.this_node[&id("Home")].is_empty());
    }
}
