use std::collections::HashSet;

use crate::{
    config::Config,
    consts,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ZoneLoc,
        },
        identifier::Identifier,
    },
    validator::types::{ValidationError, ValidationReport},
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
        refs.insert(AllowFromRef::nested(
            node_name.clone(),
            consts::HUB_NAME
                .parse()
                .expect("the hub's name is a valid identifier"),
        ));

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
