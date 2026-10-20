use std::collections::HashSet;

use crate::{
    config::Config,
    consts,
    model::validator::types::{ValidationError, ValidationReport},
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ZoneLoc,
        },
        identifier::Identifier,
    },
};

fn add_name(
    name: &Identifier,
    node_name: Option<&Identifier>,
    global_refs: &mut HashSet<AllowFromRef>,
    local_names: Option<&mut HashSet<Identifier>>,
    node_prefixes: Option<&[String]>,
    report: &mut ValidationReport,
    locate: impl FnOnce() -> ConfigLocation,
) {
    if node_name.is_some() && consts::RESERVED_LOCAL_NAMES.contains(&name.as_ref()) {
        report.errors.push(ValidationError::ReservedName {
            name: name.clone(),
            at: locate(),
        });
        return;
    }

    if let Some(node_prefixes) = node_prefixes {
        for node_prefix in node_prefixes {
            if name.as_ref().starts_with(node_prefix) {
                report.errors.push(ValidationError::InvalidPrefix {
                    name: name.clone(),
                    prefix: node_prefix.clone(),
                    at: locate(),
                });
                return;
            }
        }
    }

    if let Some(local_names) = local_names {
        if local_names.contains(name) {
            report.errors.push(ValidationError::LocalNameCollision {
                name: name.clone(),
                at: locate(),
            });
            return;
        }

        local_names.insert(name.clone());
    }

    let final_name = match node_name {
        None => AllowFromRef::Bare(name.clone()),
        Some(node_name) => AllowFromRef::nested(node_name.clone(), name.clone()),
    };

    if global_refs.contains(&final_name) {
        report.errors.push(ValidationError::GlobalNameCollision {
            name: name.clone(),
            at: locate(),
        });
        return;
    }

    if node_name.is_some() && global_refs.contains(&AllowFromRef::Bare(name.clone())) {
        report.errors.push(ValidationError::LocalShadowsGlobal {
            name: name.clone(),
            at: locate(),
        });
        return;
    }

    global_refs.insert(final_name);
}

pub(super) fn validate_names(
    config: &Config,
    report: &mut ValidationReport,
) -> HashSet<AllowFromRef> {
    let node_prefixes: Vec<String> = config
        .nodes
        .keys()
        .map(|node_name| format!("{node_name}_"))
        .collect();

    let mut refs: HashSet<AllowFromRef> = HashSet::new();
    refs.insert(AllowFromRef::SelfNode);

    // Pass 1: every global name (clients, then nodes) is registered before any local
    // name is checked. Local names are checked against the global names seen so far
    // (`LocalShadowsGlobal`), so registering a node's name in the same loop as its
    // locals would miss a node that sorts after the one holding the local name.
    for client_name in config.clients.keys() {
        add_name(client_name, None, &mut refs, None, None, report, || {
            ConfigLocation::Client(client_name.clone(), ClientLoc::Root)
        });
    }

    for node_name in config.nodes.keys() {
        add_name(node_name, None, &mut refs, None, None, report, || {
            ConfigLocation::Node(node_name.clone(), NodeLoc::Root)
        });
    }

    // Pass 2: each node's local names (zones, devices and hub clients).
    for (node_name, node) in &config.nodes {
        let mut node_identifiers = HashSet::new();
        node_identifiers.insert(node_name.clone());

        for (zone_name, zone) in &node.zones {
            add_name(
                zone_name,
                Some(node_name),
                &mut refs,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Zone(zone_name.clone(), ZoneLoc::Root),
                    )
                },
            );

            for device_name in zone.devices.keys() {
                add_name(
                    device_name,
                    Some(node_name),
                    &mut refs,
                    Some(&mut node_identifiers),
                    Some(&node_prefixes),
                    report,
                    || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::Zone(
                                zone_name.clone(),
                                ZoneLoc::Device(device_name.clone(), DeviceLoc::Root),
                            ),
                        )
                    },
                )
            }
        }

        let Some(hub) = &node.hub else { continue };

        // The hub itself, by its reserved name.
        refs.insert(AllowFromRef::nested(node_name.clone(), Identifier::hub()));

        for client_name in hub.clients.keys() {
            add_name(
                client_name,
                Some(node_name),
                &mut refs,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Hub(HubLoc::Client(client_name.clone(), HubClientLoc::Root)),
                    )
                },
            )
        }
    }

    refs
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::{
            HUB_HOME,
            types::{ValidationError, ValidationReport},
        },
        test_support::{error_at, has_error, report},
    };

    #[test]
    fn names_global_name_collision() {
        // Node and client share the name "Phone".
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Phone:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::GlobalNameCollision { name, .. } if name == "Phone")
        ));
    }

    #[test]
    fn names_local_name_collision() {
        // Zone "printer" and device "printer" in the same node share a local name.
        let r = report(
            "
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
      printer:
        address: 192.168.2.1/24
        devices:
          printer:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:FF
",
        );
        // The device "printer" (inside zone "printer") is the second use of the
        // name, so it's the one flagged — at its own nested location.
        assert!(error_at(
            &r,
            "nodes.Home.zones.printer.devices.printer",
            |e| matches!(e, ValidationError::LocalNameCollision { name, .. } if name == "printer")
        ));
    }

    #[test]
    fn names_local_shadows_global() {
        // Global client "Phone"; a device in Home is also named "Phone".
        let r = report(
            "
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
        devices:
          Phone:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Phone")
        ));
    }

    // A local name equal to another node's name must be flagged no matter how the
    // two names sort. Nodes are walked in sorted order, so the two tests below put
    // the shadowed node before and after the node holding the local name.
    #[test]
    fn names_local_shadows_node_sorting_before() {
        // Device "Cabin" on node "Home"; node "Cabin" sorts before "Home".
        let r = report(
            "
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
        devices:
          Cabin:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:FF
  Cabin:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.zones.lan.devices.Cabin",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Cabin")
        ));
    }

    #[test]
    fn names_local_shadows_node_sorting_after() {
        // Device "Zeta" on node "Alpha"; node "Zeta" sorts after "Alpha", so it has
        // not been registered yet when Alpha's local names are checked — unless all
        // global names are collected first.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Alpha:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          Zeta:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:FF
  Zeta:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        assert!(error_at(
            &r,
            "nodes.Alpha.zones.lan.devices.Zeta",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Zeta")
        ));
    }

    #[test]
    fn names_invalid_prefix() {
        // Zone "Home_lan" starts with the reserved prefix "Home_" (node "Home" exists).
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      Home_lan:
        address: 192.168.1.1/24
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::InvalidPrefix { name, .. } if name == "Home_lan")
        ));
    }

    #[test]
    fn names_same_local_across_nodes_is_ok() {
        // Both Home and Cabin can have a zone named "lan" — local names don't collide cross-node.
        let r = report(
            "
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
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::LocalNameCollision { .. }
        )));
    }

    #[test]
    fn hub_client_names_share_the_node_namespace() {
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      lan:
        address: 192.168.1.1/24
    hub:
      network: 10.100.49.0/24
      clients:
        lan:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
        Phone:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: 10.100.49.11
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.lan",
            |e| matches!(e, ValidationError::LocalNameCollision { name, .. } if name == "lan")
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.Phone",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Phone")
        ));
    }

    fn reserved_name_at(r: &ValidationReport, path: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::ReservedName { name, .. } if name == "hub"),
        )
    }

    #[test]
    fn hub_is_a_reserved_local_name() {
        // Reserved on every node, with or without a hub: `{Node}.hub` refers to
        // the node's hub network.
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      hub:
        address: 192.168.1.1/24
      lan:
        address: 192.168.2.1/24
        devices:
          hub:
            ip: 192.168.2.10
            macs: AA:BB:CC:DD:EE:01
"
        ));
        assert!(reserved_name_at(&r, "nodes.Home.zones.hub"));
        assert!(reserved_name_at(&r, "nodes.Home.zones.lan.devices.hub"));

        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        hub:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
"
        ));
        assert!(reserved_name_at(&r, "nodes.Home.hub.clients.hub"));
    }
}
