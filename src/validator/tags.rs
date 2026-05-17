use std::collections::HashSet;

use crate::{
    config::Config,
    validator::{
        types::{ConfigPath, ValidationError, ValidationReport},
        utils::is_valid_identifier,
    },
};

fn add_tags(
    tags: impl IntoIterator<Item = impl AsRef<str>>,
    tags_set: &mut HashSet<String>,
    report: &mut ValidationReport,
    names: &HashSet<String>,
    make_path: impl Fn() -> ConfigPath,
) {
    for tag in tags {
        let tag = tag.as_ref();
        if !is_valid_identifier(tag) {
            report.errors.push(ValidationError::InvalidTagName {
                tag: tag.to_owned(),
                at: make_path(),
            });
            continue;
        }

        if names.contains(tag) {
            report.errors.push(ValidationError::TagWithNameCollision {
                tag: tag.to_owned(),
                at: make_path(),
            });
            continue;
        }

        tags_set.insert(tag.to_owned());
    }
}

pub(super) fn validate_tags(
    config: &Config,
    report: &mut ValidationReport,
    names: &HashSet<String>,
) -> HashSet<String> {
    let mut tags = HashSet::new();

    for (client_name, client) in &config.clients {
        add_tags(&client.tags, &mut tags, report, names, || {
            ConfigPath::new(["clients", client_name, "tags"])
        });
    }

    for (node_name, node) in &config.nodes {
        add_tags(&node.tags, &mut tags, report, names, || {
            ConfigPath::new(["nodes", node_name, "tags"])
        });

        for (zone_name, zone) in &node.zones {
            add_tags(&zone.tags, &mut tags, report, names, || {
                ConfigPath::new(["nodes", node_name, "zones", zone_name, "tags"])
            });

            for (device_name, device) in &zone.devices {
                add_tags(&device.tags, &mut tags, report, names, || {
                    ConfigPath::new([
                        "nodes",
                        node_name,
                        "zones",
                        zone_name,
                        "devices",
                        device_name,
                        "tags",
                    ])
                });
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            add_tags(&vpn_interface.tags, &mut tags, report, names, || {
                ConfigPath::new([
                    "nodes",
                    node_name,
                    "vpnInterfaces",
                    vpn_interface_name,
                    "tags",
                ])
            });

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                add_tags(&vpn_interface_client.tags, &mut tags, report, names, || {
                    ConfigPath::new([
                        "nodes",
                        node_name,
                        "vpnInterfaces",
                        vpn_interface_name,
                        "clients",
                        vpn_interface_client_name,
                        "tags",
                    ])
                });
            }
        }
    }

    tags
}
