use std::collections::HashSet;

use crate::{
    config::Config,
    types::{allow_from_ref::AllowFromRef, identifier::Identifier},
    validator::types::{ConfigPath, ValidationError, ValidationReport},
};

fn add_tags<'a>(
    tags: impl IntoIterator<Item = &'a Identifier>,
    tags_set: &mut HashSet<AllowFromRef>,
    report: &mut ValidationReport,
    global_refs: &HashSet<AllowFromRef>,
    make_path: impl Fn() -> ConfigPath,
) {
    for tag in tags {
        let reference = AllowFromRef::Bare(tag.clone());
        if global_refs.contains(&reference) {
            let AllowFromRef::Bare(tag) = reference else {
                unreachable!()
            };
            report.errors.push(ValidationError::TagWithNameCollision {
                tag,
                at: make_path(),
            });
            continue;
        }

        tags_set.insert(reference);
    }
}

pub(super) fn validate_tags(
    config: &Config,
    report: &mut ValidationReport,
    global_refs: &HashSet<AllowFromRef>,
) -> HashSet<AllowFromRef> {
    let mut tags = HashSet::new();

    for (client_name, client) in &config.clients {
        add_tags(&client.tags, &mut tags, report, global_refs, || {
            ConfigPath::new(["clients", client_name.as_ref(), "tags"])
        });
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

        add_tags(&node.tags, &mut tags, report, global_refs, || {
            make_path().extend(["tags"])
        });

        for (zone_name, zone) in &node.zones {
            let make_path = || make_path().extend(["zones", zone_name.as_ref()]);

            add_tags(&zone.tags, &mut tags, report, global_refs, || {
                make_path().extend(["tags"])
            });

            for (device_name, device) in &zone.devices {
                add_tags(&device.tags, &mut tags, report, global_refs, || {
                    make_path().extend(["devices", device_name.as_ref(), "tags"])
                });
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let make_path = || make_path().extend(["vpnInterfaces", vpn_interface_name.as_ref()]);

            add_tags(&vpn_interface.tags, &mut tags, report, global_refs, || {
                make_path().extend(["tags"])
            });

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                add_tags(
                    &vpn_interface_client.tags,
                    &mut tags,
                    report,
                    global_refs,
                    || make_path().extend(["clients", vpn_interface_client_name.as_ref(), "tags"]),
                );
            }
        }
    }

    tags
}
