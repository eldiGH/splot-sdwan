use std::collections::HashSet;

use crate::{
    config::Config,
    types::{allow_from_ref::AllowFromRef, identifier::Identifier},
    validator::types::{ConfigPath, ValidationError, ValidationReport},
};

fn add_name(
    name: &Identifier,
    node_name: Option<&Identifier>,
    global_refs: &mut HashSet<AllowFromRef>,
    local_names: Option<&mut HashSet<Identifier>>,
    node_prefixes: Option<&[String]>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    if let Some(node_prefixes) = node_prefixes {
        for node_prefix in node_prefixes {
            if name.as_ref().starts_with(node_prefix) {
                report.errors.push(ValidationError::InvalidPrefix {
                    name: name.clone(),
                    prefix: node_prefix.clone(),
                    at: make_path(),
                });
                return;
            }
        }
    }

    if let Some(local_names) = local_names {
        if local_names.contains(name) {
            report.errors.push(ValidationError::LocalNameCollision {
                name: name.clone(),
                at: make_path(),
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
            at: make_path(),
        });
        return;
    }

    if node_name.is_some() && global_refs.contains(&AllowFromRef::Bare(name.clone())) {
        report.errors.push(ValidationError::LocalShadowsGlobal {
            name: name.clone(),
            at: make_path(),
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

    for client_name in config.clients.keys() {
        add_name(client_name, None, &mut refs, None, None, report, || {
            ConfigPath::new(["clients", client_name.as_ref()])
        });
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

        let mut node_identifiers = HashSet::new();
        node_identifiers.insert(node_name.clone());

        add_name(node_name, None, &mut refs, None, None, report, make_path);

        for (zone_name, zone) in &node.zones {
            let make_path = || make_path().extend(["zones", zone_name.as_ref()]);

            add_name(
                zone_name,
                Some(node_name),
                &mut refs,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                make_path,
            );

            for device_name in zone.devices.keys() {
                let make_path = || make_path().extend(["devices", device_name.as_ref()]);

                add_name(
                    device_name,
                    Some(node_name),
                    &mut refs,
                    Some(&mut node_identifiers),
                    Some(&node_prefixes),
                    report,
                    make_path,
                )
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let make_path = || make_path().extend(["vpnInterfaces", vpn_interface_name.as_ref()]);

            add_name(
                vpn_interface_name,
                Some(node_name),
                &mut refs,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                make_path,
            );

            for client_name in vpn_interface.clients.keys() {
                let make_path = || make_path().extend(["clients", client_name.as_ref()]);

                add_name(
                    client_name,
                    Some(node_name),
                    &mut refs,
                    Some(&mut node_identifiers),
                    Some(&node_prefixes),
                    report,
                    make_path,
                )
            }
        }
    }

    refs
}
