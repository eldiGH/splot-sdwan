use std::collections::HashSet;

use crate::{
    config::Config,
    consts,
    validator::{
        types::{ConfigPath, ValidationError, ValidationReport},
        utils::is_valid_identifier,
    },
};

fn add_name(
    name: &str,
    node_name: Option<&str>,
    global_names: &mut HashSet<String>,
    local_names: Option<&mut HashSet<String>>,
    node_prefixes: Option<&[String]>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    if !is_valid_identifier(name) {
        report.errors.push(ValidationError::InvalidName {
            name: name.to_owned(),
            at: make_path(),
        });
        return;
    }

    if name.starts_with(consts::SPLOT_SECTION_PREFIX) {
        report.errors.push(ValidationError::InvalidPrefix {
            name: name.to_owned(),
            prefix: consts::SPLOT_SECTION_PREFIX.to_owned(),
            at: make_path(),
        });
        return;
    }

    if let Some(node_prefixes) = node_prefixes {
        for node_prefix in node_prefixes {
            if name.starts_with(node_prefix) {
                report.errors.push(ValidationError::InvalidPrefix {
                    name: name.to_owned(),
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
                name: name.to_owned(),
                at: make_path(),
            });
            return;
        }

        local_names.insert(name.to_owned());
    }

    let final_name = match node_name {
        None => name.to_owned(),
        Some(node_name) => format!("{node_name}.{name}"),
    };

    if global_names.contains(&final_name) || global_names.contains(name) {
        report.errors.push(ValidationError::GlobalNameCollision {
            name: name.to_owned(),
            at: make_path(),
        });
    } else {
        global_names.insert(final_name);
    }
}

pub(super) fn validate_names(config: &Config, report: &mut ValidationReport) -> HashSet<String> {
    let node_prefixes: Vec<String> = config
        .nodes
        .keys()
        .map(|node_name| format!("{node_name}_"))
        .collect();

    let mut names = HashSet::new();
    names.insert(consts::CURRENT_NODE_IDENTIFIER.to_owned());

    for client_name in config.clients.keys() {
        add_name(client_name, None, &mut names, None, None, report, || {
            ConfigPath::new(["clients", client_name])
        });
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name]);

        let mut node_identifiers = HashSet::new();
        node_identifiers.insert(node_name.clone());

        add_name(node_name, None, &mut names, None, None, report, make_path);

        for (zone_name, zone) in &node.zones {
            let make_path = || make_path().extend(["zones", zone_name]);

            add_name(
                zone_name,
                Some(node_name),
                &mut names,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                make_path,
            );

            for device_name in zone.devices.keys() {
                let make_path = || make_path().extend(["devices", device_name]);

                add_name(
                    device_name,
                    Some(node_name),
                    &mut names,
                    Some(&mut node_identifiers),
                    Some(&node_prefixes),
                    report,
                    make_path,
                )
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let make_path = || make_path().extend(["vpnInterfaces", vpn_interface_name]);

            add_name(
                vpn_interface_name,
                Some(node_name),
                &mut names,
                Some(&mut node_identifiers),
                Some(&node_prefixes),
                report,
                make_path,
            );

            for client_name in vpn_interface.clients.keys() {
                let make_path = || make_path().extend(["clients", client_name]);

                add_name(
                    client_name,
                    Some(node_name),
                    &mut names,
                    Some(&mut node_identifiers),
                    Some(&node_prefixes),
                    report,
                    make_path,
                )
            }
        }
    }

    names
}
