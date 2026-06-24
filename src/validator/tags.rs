use std::collections::HashSet;

use crate::{
    config::Config,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, VpnClientLoc, VpnLoc, ZoneLoc,
        },
        identifier::Identifier,
    },
    validator::types::{ValidationError, ValidationReport},
};

fn add_tags<'a>(
    tags: impl IntoIterator<Item = &'a Identifier>,
    tags_set: &mut HashSet<AllowFromRef>,
    report: &mut ValidationReport,
    global_refs: &HashSet<AllowFromRef>,
    locate: impl Fn() -> ConfigLocation,
) {
    for tag in tags {
        let reference = AllowFromRef::Bare(tag.clone());
        if global_refs.contains(&reference) {
            let AllowFromRef::Bare(tag) = reference else {
                unreachable!()
            };
            report
                .errors
                .push(ValidationError::TagWithNameCollision { tag, at: locate() });
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
            ConfigLocation::Client(client_name.clone(), ClientLoc::Tags)
        });
    }

    for (node_name, node) in &config.nodes {
        add_tags(&node.tags, &mut tags, report, global_refs, || {
            ConfigLocation::Node(node_name.clone(), NodeLoc::Tags)
        });

        for (zone_name, zone) in &node.zones {
            add_tags(&zone.tags, &mut tags, report, global_refs, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(zone_name.clone(), ZoneLoc::Tags),
                )
            });

            for (device_name, device) in &zone.devices {
                add_tags(&device.tags, &mut tags, report, global_refs, || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Zone(
                            zone_name.clone(),
                            ZoneLoc::Device(device_name.clone(), DeviceLoc::Tags),
                        ),
                    )
                });
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            add_tags(&vpn_interface.tags, &mut tags, report, global_refs, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::VpnInterface(vpn_interface_name.clone(), VpnLoc::Tags),
                )
            });

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                add_tags(
                    &vpn_interface_client.tags,
                    &mut tags,
                    report,
                    global_refs,
                    || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::VpnInterface(
                                vpn_interface_name.clone(),
                                VpnLoc::Client(
                                    vpn_interface_client_name.clone(),
                                    VpnClientLoc::Tags,
                                ),
                            ),
                        )
                    },
                );
            }
        }
    }

    tags
}
