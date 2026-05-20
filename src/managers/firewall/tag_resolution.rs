use std::{collections::HashMap, iter};

use crate::{
    config::{Client, Config, Node},
    managers::firewall::types::TagResolution,
    types::{
        allow_from_ref::AllowFromRef, identifier::Identifier, ip::Ipv4Network, zone_ref::ZoneRef,
    },
};

fn add_tags(
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
    network: Ipv4Network,
    tags: impl IntoIterator<Item = AllowFromRef>,
    zone_name: &ZoneRef,
) {
    for tag in tags {
        tags_map
            .entry(tag)
            .or_default()
            .entry(zone_name.clone())
            .or_default()
            .insert(network);
    }
}

fn add_current_node_identifier_tag(
    node: &Node,
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
) {
    for (zone_name, zone) in &node.zones {
        add_tags(
            tags_map,
            Ipv4Network::host(zone.address.ip()),
            [AllowFromRef::SelfNode],
            &ZoneRef::Named(zone_name.clone()),
        );
    }

    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        add_tags(
            tags_map,
            Ipv4Network::host(vpn_interface.address.ip()),
            [AllowFromRef::SelfNode],
            &ZoneRef::Named(vpn_interface_name.clone()),
        );
    }
}

fn add_node_tag(
    node_name: &Identifier,
    node: &Node,
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
) {
    let node_tags = iter::once(node_name.to_owned())
        .chain(node.tags.iter().cloned())
        .map(AllowFromRef::Bare);

    for (zone_name, zone) in &node.zones {
        add_tags(
            tags_map,
            zone.address.network(),
            node_tags.clone(),
            &ZoneRef::Named(zone_name.clone()),
        );
    }

    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        add_tags(
            tags_map,
            vpn_interface.address.network(),
            node_tags.clone(),
            &ZoneRef::Named(vpn_interface_name.clone()),
        )
    }
}

fn add_client_tag(
    client_name: &Identifier,
    client: &Client,
    own_name: &Identifier,
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
) {
    let tags: Vec<AllowFromRef> = iter::once(client_name.clone())
        .chain(client.tags.iter().cloned())
        .map(AllowFromRef::Bare)
        .collect();

    if let Some(mesh_ip) = client.mesh_ip {
        add_tags(
            tags_map,
            Ipv4Network::host(mesh_ip),
            tags.iter().cloned(),
            &ZoneRef::Mesh,
        );
    }

    for (node_name, networks) in &client.ips {
        for (local_name, ip) in networks {
            let zone_ref = if node_name == own_name {
                ZoneRef::Named(local_name.clone())
            } else {
                ZoneRef::Mesh
            };

            add_tags(
                tags_map,
                Ipv4Network::host(*ip),
                tags.iter().cloned(),
                &zone_ref,
            );
        }
    }
}

fn add_zones_tags(
    node_name: &Identifier,
    node: &Node,
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
) {
    for (zone_name, zone) in &node.zones {
        let zone_ref = ZoneRef::Named(zone_name.clone());
        let zone_tags = iter::once(AllowFromRef::nested(node_name.clone(), zone_name.clone()))
            .chain(zone.tags.iter().cloned().map(AllowFromRef::Bare));

        add_tags(tags_map, zone.address.network(), zone_tags, &zone_ref);

        for (device_name, device) in &zone.devices {
            let device_tags =
                iter::once(AllowFromRef::nested(node_name.clone(), device_name.clone()))
                    .chain(device.tags.iter().cloned().map(AllowFromRef::Bare));
            add_tags(
                tags_map,
                Ipv4Network::host(device.ip),
                device_tags,
                &zone_ref,
            );
        }
    }
}

fn add_vpn_interfaces_tags(
    node_name: &Identifier,
    node: &Node,
    tags_map: &mut HashMap<AllowFromRef, TagResolution>,
) {
    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        let zone_ref = ZoneRef::Named(vpn_interface_name.clone());
        let vpn_interface_tags = iter::once(AllowFromRef::nested(
            node_name.clone(),
            vpn_interface_name.clone(),
        ))
        .chain(vpn_interface.tags.iter().cloned().map(AllowFromRef::Bare));

        add_tags(
            tags_map,
            vpn_interface.address.network(),
            vpn_interface_tags,
            &zone_ref,
        );

        for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
            let vpn_interface_client_tags = iter::once(AllowFromRef::nested(
                node_name.clone(),
                vpn_interface_client_name.clone(),
            ))
            .chain(
                vpn_interface_client
                    .tags
                    .iter()
                    .cloned()
                    .map(AllowFromRef::Bare),
            );

            add_tags(
                tags_map,
                Ipv4Network::host(vpn_interface_client.ip),
                vpn_interface_client_tags,
                &zone_ref,
            );
        }
    }
}

pub fn build_tags_resolution_map(
    config: &Config,
    own_name: &Identifier,
) -> HashMap<AllowFromRef, TagResolution> {
    let mut tags_map: HashMap<AllowFromRef, TagResolution> = HashMap::new();

    for (node_name, node) in &config.nodes {
        if node_name == own_name {
            add_current_node_identifier_tag(node, &mut tags_map);
        }

        add_node_tag(node_name, node, &mut tags_map);

        add_zones_tags(node_name, node, &mut tags_map);
        add_vpn_interfaces_tags(node_name, node, &mut tags_map);
    }

    for (client_name, client) in &config.clients {
        add_client_tag(client_name, client, own_name, &mut tags_map);
    }

    tags_map
}
