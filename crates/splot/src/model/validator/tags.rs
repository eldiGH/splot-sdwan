use std::collections::HashSet;

use crate::{
    config::Config,
    model::validator::types::{ValidationError, ValidationReport},
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ZoneLoc,
        },
        identifier::Identifier,
    },
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
            report.errors.push(ValidationError::TagWithNameCollision {
                tag: tag.clone(),
                at: locate(),
            });
        } else {
            tags_set.insert(reference);
        }
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

        let Some(hub) = &node.hub else { continue };

        add_tags(&hub.tags, &mut tags, report, global_refs, || {
            ConfigLocation::Node(node_name.clone(), NodeLoc::Hub(HubLoc::Tags))
        });

        for (client_name, client) in &hub.clients {
            add_tags(&client.tags, &mut tags, report, global_refs, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Hub(HubLoc::Client(client_name.clone(), HubClientLoc::Tags)),
                )
            });
        }
    }

    tags
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::{HUB_HOME, types::ValidationError},
        test_support::{error_at, has_error, report},
    };

    #[test]
    fn tags_collision_with_node_name() {
        // Tag "Home" on Phone collides with node name "Home".
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
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    tags: Home
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::TagWithNameCollision { tag, .. } if tag == "Home")
        ));
    }

    #[test]
    fn tags_same_tag_multiple_places_ok() {
        // Tag "admin" applied to both Phone and Home's zone — no error.
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
    zones:
      lan:
        address: 192.168.1.1/24
        tags: admin
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    tags: admin
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::TagWithNameCollision { .. }
        )));
    }

    #[test]
    fn hub_tags_must_not_collide_with_global_names() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      tags: Phone
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          tags: Phone
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.1.10
"
        ));
        for path in ["nodes.Home.hub.tags", "nodes.Home.hub.clients.camera.tags"] {
            assert!(
                error_at(&r, path, |e| matches!(
                    e,
                    ValidationError::TagWithNameCollision { .. }
                )),
                "{path}"
            );
        }
    }
}
