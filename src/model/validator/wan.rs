use std::collections::{BTreeMap, HashSet};

use crate::{
    config::{Client, Config, Node, ServiceHost, ServiceWan},
    consts,
    model::{
        host::{Host, HostAddress, Place},
        validator::types::{ValidationError, ValidationReport, ValidationWarning},
    },
    types::{
        config_location::{ConfigLocation, NodeLoc, ServiceLoc, WanLoc, ZoneLoc},
        identifier::{Identifier, NestedIdentifier},
        wan_via_target::WanViaTarget,
    },
};

/// Why a `wan.via` node has nothing of the host's to forward to.
enum TargetError {
    QualifiedOnNonClient,
    Unreachable,
    NetworkMissing { network: Identifier },
    ClientNotOnNetwork { network: Identifier },
}

impl TargetError {
    fn into_validation_error(self, node: &Identifier, at: ConfigLocation) -> ValidationError {
        let node = node.clone();

        match self {
            Self::QualifiedOnNonClient => ValidationError::WanViaQualifiedOnNonClient { at },
            Self::Unreachable => ValidationError::WanViaUnreachable { node, at },
            Self::NetworkMissing { network } => {
                ValidationError::WanViaNetworkMissing { node, network, at }
            }
            Self::ClientNotOnNetwork { network } => {
                ValidationError::WanViaClientNotOnNetwork { node, network, at }
            }
        }
    }
}

/// Where the client's address that `node` forwards to lives. Its mesh IP wins:
/// every node reaches it. Otherwise its IP on one of the node's zones (it has at
/// most one there). The qualified form `{Node}.{Zone}` picks the zone.
fn client_target(client: &Client, via: &WanViaTarget, node: &Node) -> Result<Place, TargetError> {
    match via {
        WanViaTarget::Bare(node_name) => {
            if client.mesh_ip.is_some() {
                return Ok(Place::Mesh);
            }

            client
                .ips
                .get(node_name)
                .into_iter()
                .flatten()
                .find(|(zone_name, _)| node.zones.contains_key(*zone_name))
                .map(|(zone_name, _)| Place::Zone {
                    node: node_name.clone(),
                    zone: zone_name.clone(),
                })
                .ok_or(TargetError::Unreachable)
        }
        WanViaTarget::Qualified(NestedIdentifier {
            node: node_name,
            local: zone_name,
        }) => {
            if !node.zones.contains_key(zone_name) {
                return Err(TargetError::NetworkMissing {
                    network: zone_name.clone(),
                });
            }

            if client.ip_in_zone(node_name, zone_name).is_none() {
                return Err(TargetError::ClientNotOnNetwork {
                    network: zone_name.clone(),
                });
            }

            Ok(Place::Zone {
                node: node_name.clone(),
                zone: zone_name.clone(),
            })
        }
    }
}

/// Where the host's address that `node` forwards to lives. A node is reached on
/// its mesh IP, a device or a hub client on its one IP. Only a global client
/// can have more than one, so only its services may pick one by `{Node}.{Zone}`.
fn target_place(host: ServiceHost, via: &WanViaTarget, node: &Node) -> Result<Place, TargetError> {
    match host {
        ServiceHost::Client { client, .. } => client_target(client, via, node),
        _ if matches!(via, WanViaTarget::Qualified(_)) => Err(TargetError::QualifiedOnNonClient),
        ServiceHost::Node { .. } => Ok(Place::Mesh),
        ServiceHost::Device {
            node_name,
            zone_name,
            ..
        } => Ok(Place::Zone {
            node: node_name.clone(),
            zone: zone_name.clone(),
        }),
        ServiceHost::HubClient { node_name, .. } => Ok(Place::Hub {
            node: node_name.clone(),
        }),
    }
}

/// Checks every `wan.via` node of a service, and finds what each one forwards it
/// to: one of the host's addresses. A target that fails a check is left out, and
/// so is one whose address failed its own (already reported).
pub(super) fn check_targets<'a>(
    config: &'a Config,
    wan: &'a ServiceWan,
    host: ServiceHost,
    built_host: Option<&Host>,
    wan_nodes_used: &mut HashSet<&'a Identifier>,
    report: &mut ValidationReport,
) -> BTreeMap<Identifier, HostAddress> {
    let locate = || host.to_location(ServiceLoc::Wan(WanLoc::Via));
    let mut targets = BTreeMap::new();

    for via in &wan.via {
        let node_name = via.node();

        let Some(node) = config.nodes.get(node_name) else {
            report.errors.push(ValidationError::InvalidWanVia {
                node_name: node_name.clone(),
                at: locate(),
            });
            continue;
        };

        if node.wan_zone.is_none() {
            report.errors.push(ValidationError::WanViaNodeNoWanZone {
                node_name: node_name.clone(),
                at: locate(),
            });
        }

        wan_nodes_used.insert(node_name);

        let place = match target_place(host, via, node) {
            Ok(place) => place,
            Err(error) => {
                report
                    .errors
                    .push(error.into_validation_error(node_name, locate()));
                continue;
            }
        };

        let address = built_host
            .into_iter()
            .flat_map(Host::addresses)
            .find(|address| *address.place() == place);

        if let Some(address) = address {
            targets.insert(node_name.clone(), address.clone());
        }
    }

    targets
}

/// A `wanZone` no service is exposed through is a warning.
pub(super) fn warn_unused_wan_zones(
    config: &Config,
    wan_nodes_used: &HashSet<&Identifier>,
    report: &mut ValidationReport,
) {
    for (node_name, node) in &config.nodes {
        if node.wan_zone.is_some() && !wan_nodes_used.contains(node_name) {
            report.warnings.push(ValidationWarning::UnusedWanZone {
                at: ConfigLocation::Node(node_name.clone(), NodeLoc::WanZone),
            })
        }
    }
}

/// A `wanZone` must not reuse a zone's name or the mesh interface's.
pub(super) fn check_wan_zones(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        let Some(wan_zone) = &node.wan_zone else {
            continue;
        };

        let at = || ConfigLocation::Node(node_name.clone(), NodeLoc::WanZone);

        if wan_zone == consts::MESH_INTERFACE_NAME {
            report.errors.push(ValidationError::WanZoneReservedName {
                wan_zone: wan_zone.clone(),
                at: at(),
            });
            continue;
        }

        if node.zones.contains_key(wan_zone) {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(wan_zone.clone(), ZoneLoc::Root),
                ),
                at: at(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{
            Network,
            host::HostRef,
            service::Wan,
            validator::{Checked, check},
        },
        test_support::{checked, config},
    };

    // One node with two zones. The clients cover every branch of client_target.
    const CLIENTS: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
      iot:
        address: 192.168.3.1/24
clients:
  # has meshIp AND a zone IP; mesh must win
  PhoneWithMesh:
    meshIp: 10.100.0.100
    ips:
      Home:
        lan: 192.168.1.50
  # no meshIp, zone IP only
  ZoneOnly:
    ips:
      Home:
        lan: 192.168.1.60
  # no meshIp, no IPs on Home at all
  Nowhere: {}
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn via(s: &str) -> WanViaTarget {
        s.parse().unwrap()
    }

    fn home_lan() -> Place {
        Place::Zone {
            node: id("Home"),
            zone: id("lan"),
        }
    }

    /// Where `client`'s target for `via` lives, on the fixture's Home.
    fn target(client: &str, via_target: &str) -> Result<Place, TargetError> {
        let config = config(CLIENTS);
        client_target(
            &config.clients[&id(client)],
            &via(via_target),
            &config.nodes[&id("Home")],
        )
    }

    // --- Bare via: the mesh IP, else the IP on the node's zone ---

    #[test]
    fn bare_mesh_ip_wins_over_zone_ip() {
        assert!(matches!(target("PhoneWithMesh", "Home"), Ok(Place::Mesh)));
    }

    #[test]
    fn bare_zone_ip_when_no_mesh() {
        assert!(matches!(target("ZoneOnly", "Home"), Ok(place) if place == home_lan()));
    }

    #[test]
    fn bare_unreachable_when_no_ips_on_node() {
        assert!(matches!(
            target("Nowhere", "Home"),
            Err(TargetError::Unreachable)
        ));
    }

    // --- Qualified via: the IP on that zone ---

    #[test]
    fn qualified_zone_resolves_even_with_a_mesh_ip() {
        assert!(matches!(target("PhoneWithMesh", "Home.lan"), Ok(place) if place == home_lan()));
    }

    #[test]
    fn qualified_missing_network_on_node() {
        assert!(matches!(
            target("ZoneOnly", "Home.missing_net"),
            Err(TargetError::NetworkMissing { network }) if network == id("missing_net")
        ));
    }

    #[test]
    fn qualified_client_not_on_network() {
        // ZoneOnly has no iot IP, but iot exists on Home.
        assert!(matches!(
            target("ZoneOnly", "Home.iot"),
            Err(TargetError::ClientNotOnNetwork { network }) if network == id("iot")
        ));
    }

    // --- Targets in the model ---

    // Home exposes its nas through itself and through Cabin, and Phone through
    // Home on its lan IP (though it has a mesh IP).
    const EXPOSED: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          nas:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
            services:
              https:
                port: 443
                proto: tcp
                wan: { via: [Home, Cabin], sources: 198.51.100.0/24 }
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.1.10
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home: { lan: 192.168.1.50 }
    services:
      web: { port: 8080, proto: tcp, wan: { via: Home.lan } }
";

    fn exposure<'a>(network: &'a Network, host: &HostRef, service: &str) -> &'a Wan {
        network.services[host][&id(service)]
            .wan()
            .expect("service is exposed")
    }

    #[test]
    fn each_via_node_forwards_to_one_of_the_hosts_addresses() {
        let (_, network) = checked(EXPOSED);
        let nas = exposure(
            &network,
            &HostRef::Local {
                node: id("Home"),
                name: id("nas"),
            },
            "https",
        );

        for node in ["Home", "Cabin"] {
            let target = nas.target(&id(node)).expect("a target on every via node");
            assert_eq!(target.ip().to_string(), "192.168.1.20");
            assert_eq!(*target.place(), home_lan());
        }
        assert!(nas.target(&id("Attic")).is_none());
        assert_eq!(
            nas.sources()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["198.51.100.0/24"]
        );

        let phone = exposure(&network, &HostRef::Client(id("Phone")), "web");
        let target = phone.target(&id("Home")).unwrap();
        assert_eq!(target.ip().to_string(), "192.168.1.50");
        assert_eq!(*target.place(), home_lan());
    }

    #[test]
    fn a_target_whose_address_failed_its_check_is_no_second_error() {
        // Phone's lan IP lies outside lan: that's the one error. Its WAN target is
        // left out, not reported as unreachable.
        let yaml = EXPOSED.replace("lan: 192.168.1.50", "lan: 192.168.9.50");
        let Checked {
            services, report, ..
        } = check(&config(&yaml));

        let errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("outside subnet"), "{errors:?}");

        let wan = services[&HostRef::Client(id("Phone"))][&id("web")]
            .wan()
            .unwrap();
        assert!(wan.target(&id("Home")).is_none());
    }
}
