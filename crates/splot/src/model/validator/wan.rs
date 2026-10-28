use std::collections::{BTreeMap, HashSet};

use crate::{
    config::{Client, Config, Node, ServiceHost, ServiceWan},
    consts,
    model::{
        host::{Host, HostAddress, Place},
        platform::Platform,
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
/// so is one whose address failed its own (already reported). A node needs a
/// `wanZone` only where splot manages its firewall: elsewhere it forwards
/// nothing (a warning says so).
pub(super) fn check_targets<'a>(
    config: &'a Config,
    platforms: &BTreeMap<Identifier, Platform>,
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

        // A node whose platform failed counts as managed: its error stands.
        let firewall_managed = platforms
            .get(node_name)
            .is_none_or(|platform| platform.firewall().is_some());
        if node.wan_zone.is_none() && firewall_managed {
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

/// Whether others dial the node at the listen port of splot's WireGuard, which
/// splot then lets in from its `wanZone` (where it manages its firewall). A node
/// whose platform failed counts as managed: its error stands.
fn listens_on_wan(node: &Node, platform: Option<&Platform>) -> bool {
    node.endpoint.is_some() && platform.is_none_or(|platform| platform.wireguard().is_some())
}

/// A `wanZone` nothing comes in through, no service and no listen port, is a
/// warning.
pub(super) fn warn_unused_wan_zones(
    config: &Config,
    platforms: &BTreeMap<Identifier, Platform>,
    wan_nodes_used: &HashSet<&Identifier>,
    report: &mut ValidationReport,
) {
    for (node_name, node) in &config.nodes {
        if node.wan_zone.is_some()
            && !wan_nodes_used.contains(node_name)
            && !listens_on_wan(node, platforms.get(node_name))
        {
            report.warnings.push(ValidationWarning::UnusedWanZone {
                at: ConfigLocation::Node(node_name.clone(), NodeLoc::WanZone),
            })
        }
    }
}

/// A node others dial needs a `wanZone` where splot lets its listen port in, as
/// it does a `wan.via` node's forwards. A `wanZone` must not reuse a zone's name
/// or the mesh interface's.
pub(super) fn check_wan_zones(
    config: &Config,
    platforms: &BTreeMap<Identifier, Platform>,
    report: &mut ValidationReport,
) {
    for (node_name, node) in &config.nodes {
        let Some(wan_zone) = &node.wan_zone else {
            let platform = platforms.get(node_name);
            if listens_on_wan(node, platform)
                && platform.is_none_or(|platform| platform.firewall().is_some())
            {
                report.errors.push(ValidationError::EndpointNoWanZone {
                    node_name: node_name.clone(),
                    at: ConfigLocation::Node(node_name.clone(), NodeLoc::Endpoint),
                });
            }
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
            validator::{Checked, HUB_HOME, check},
        },
        test_support::{checked, config, error_at, has_error, has_warning, report, warning_at},
    };

    // One node with two zones. The clients cover every branch of client_target.
    const CLIENTS: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
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
    platform:
      os: openwrt
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
    platform:
      os: openwrt
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
        let network = checked(EXPOSED);
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

    #[test]
    fn wan_invalid_via_node() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: NoSuchNode
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::InvalidWanVia { node_name, .. } if node_name == "NoSuchNode")
        ));
    }

    #[test]
    fn wan_via_node_without_wan_zone() {
        // Home has no wanZone, but a service uses it in wan.via. Nobody dials
        // it, so that's the only use it would have.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaNodeNoWanZone { node_name, .. } if node_name == "Home")
        ));
    }

    #[test]
    fn wan_via_a_node_that_leaves_its_firewall_alone_needs_no_wan_zone() {
        // It forwards nothing, so it has no use for one; its warning says so.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
      firewall: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::FirewallLeftAlone { unforwarded, .. } if unforwarded == &["Home.http"]
        )));
    }

    #[test]
    fn wan_via_qualified_on_non_client_service() {
        // Qualified form (Node.Network) is invalid on a node-hosted service.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.lan
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::WanViaQualifiedOnNonClient { .. }
        )));
    }

    #[test]
    fn wan_via_network_missing_on_node() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.lan
",
        );
        // Home has no zone "lan" in this fixture, so WanViaNetworkMissing fires.
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaNetworkMissing { network, .. } if network == "lan")
        ));
    }

    #[test]
    fn wan_via_client_not_on_network() {
        // Phone has an IP on "lan" but the service requests "iot" (qualified form).
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
      iot:
        address: 192.168.3.1/24
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.iot
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaClientNotOnNetwork { network, .. } if network == "iot")
        ));
    }

    #[test]
    fn wan_via_unreachable_client() {
        // Phone has no meshIp and no IPs on Cabin; forwarding via Cabin is impossible.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Cabin
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaUnreachable { node, .. } if node == "Cabin")
        ));
    }

    #[test]
    fn wan_zone_collides_with_zone_name() {
        // wanZone "lan" collides with the zone named "lan" on the same node.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: lan
    zones:
      lan:
        address: 192.168.1.1/24
",
        );
        // `at` points at the wanZone declaration; `with` at the conflicting zone.
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::WanZoneNameCollision { wan_zone, with, at }
                if wan_zone == "lan"
                    && with.to_string() == "nodes.Home.zones.lan"
                    && at.to_string() == "nodes.Home.wanZone"
        )));
    }

    #[test]
    fn wan_zone_reserved_mesh_name() {
        // wanZone "mesh" collides with the splot-managed mesh interface name — a
        // reserved-name error (no config location to point `with` at), distinct
        // from a collision with the operator's own zone.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: mesh
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.wanZone",
            |e| matches!(e, ValidationError::WanZoneReservedName { wan_zone, .. } if wan_zone == "mesh")
        ));
        // ...and it must NOT be misreported as an ordinary name collision.
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::WanZoneNameCollision { .. }
        )));
    }

    /// Home, whom Cabin dials, with the platform lines given and no wanZone;
    /// Lake, whom nobody dials, without one either.
    fn dialled(home_platform: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
{home_platform}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Lake:
    platform:
      os: openwrt
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    listenPort: 51820
    meshIp: 10.100.0.2
"
        )
    }

    #[test]
    fn a_node_others_dial_needs_a_wan_zone_to_let_its_listen_port_in() {
        let r = report(&dialled(""));
        assert!(error_at(
            &r,
            "nodes.Home.endpoint",
            |e| matches!(e, ValidationError::EndpointNoWanZone { node_name, .. } if node_name == "Home")
        ));
        // Lake dials out: the replies come back as established traffic.
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
    }

    #[test]
    fn a_node_whose_firewall_or_wireguard_is_left_alone_needs_no_wan_zone_to_be_dialled() {
        // Its firewall is the operator's; or its WireGuard is, and with it the
        // port. The warnings say so.
        for platform in ["      firewall: none", "      wireguard: none"] {
            let r = report(&dialled(platform));
            assert!(r.errors.is_empty(), "{platform}: {:?}", r.errors);
        }
    }

    #[test]
    fn wan_unused_wan_zone_warning() {
        // wanZone is declared but no service references this node in wan.via,
        // and nobody dials it.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
",
        );
        assert!(warning_at(&r, "nodes.Home.wanZone", |w| matches!(
            w,
            ValidationWarning::UnusedWanZone { .. }
        )));
    }

    #[test]
    fn the_listen_port_of_a_node_others_dial_uses_its_wan_zone() {
        let with_wan_zone = |platform: &str| {
            report(&dialled(platform).replace(
                "    meshIp: 10.100.0.1\n",
                "    meshIp: 10.100.0.1\n    wanZone: wan\n",
            ))
        };
        let unused = |w: &ValidationWarning| matches!(w, ValidationWarning::UnusedWanZone { .. });

        let r = with_wan_zone("");
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(!has_warning(&r, unused));
        // Splot doesn't open the port of WireGuard it leaves alone.
        assert!(warning_at(
            &with_wan_zone("      wireguard: none"),
            "nodes.Home.wanZone",
            unused
        ));
    }

    #[test]
    fn hub_client_service_wan_via_must_be_bare() {
        // The qualified form picks one of a global client's networks; a hub client
        // has one address.
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      lan:
        address: 192.168.1.1/24
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            http: {{ port: 80, proto: tcp, wan: {{ via: Home.lan }} }}
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.services.http.wan.via",
            |e| matches!(e, ValidationError::WanViaQualifiedOnNonClient { .. })
        ));
    }
}
