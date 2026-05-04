use std::{collections::HashMap, iter};

use crate::{
    config::{Client, Config, Node},
    consts,
    managers::firewall::types::{IpOrNetwork, TagResolution},
};

const CURRENT_NODE_IDENTIFIER: &str = "$node";

fn add_tags(
    tags_map: &mut HashMap<String, TagResolution>,
    address: IpOrNetwork,
    tags: impl IntoIterator<Item = String>,
    zone_name: &str,
) {
    for tag in tags {
        tags_map
            .entry(tag)
            .or_default()
            .entry(zone_name.to_owned())
            .or_default()
            .insert(address);
    }
}

fn scoped_current_node_identifier(identifier: &str) -> String {
    format!("{}.{identifier}", CURRENT_NODE_IDENTIFIER)
}

fn add_current_node_identifier_tag(node: &Node, tags_map: &mut HashMap<String, TagResolution>) {
    for (zone_name, zone) in &node.zones {
        let Some(address) = zone.address else {
            continue;
        };

        let zone_tags = [
            CURRENT_NODE_IDENTIFIER.to_owned(),
            scoped_current_node_identifier(zone_name),
        ];

        add_tags(
            tags_map,
            IpOrNetwork::Ip(address.ip()),
            zone_tags,
            zone_name,
        );
    }

    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        let vpn_interface_tags = [
            CURRENT_NODE_IDENTIFIER.to_owned(),
            scoped_current_node_identifier(vpn_interface_name),
        ];

        add_tags(
            tags_map,
            IpOrNetwork::Ip(vpn_interface.address.ip()),
            vpn_interface_tags,
            vpn_interface_name,
        );
    }
}

fn add_node_tag(node_name: &str, node: &Node, tags_map: &mut HashMap<String, TagResolution>) {
    let node_tags = iter::once(node_name.to_owned()).chain(node.tags.iter().cloned());
    for (zone_name, zone) in &node.zones {
        let Some(address) = zone.address else {
            continue;
        };

        add_tags(
            tags_map,
            IpOrNetwork::Network(address.network()),
            node_tags.clone(),
            zone_name,
        );
    }

    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        add_tags(
            tags_map,
            IpOrNetwork::Network(vpn_interface.address.network()),
            node_tags.clone(),
            vpn_interface_name,
        )
    }
}

fn add_client_tag(
    client_name: &str,
    client: &Client,
    own_name: &str,
    tags_map: &mut HashMap<String, TagResolution>,
) {
    let tags: Vec<String> = iter::once(client_name.to_owned())
        .chain(client.tags.iter().cloned())
        .collect();

    if let Some(mesh_ip) = client.mesh_ip {
        add_tags(
            tags_map,
            IpOrNetwork::Ip(mesh_ip),
            tags.iter().cloned(),
            consts::MESH_INTERFACE_NAME,
        );
    }

    for (node_name, networks) in &client.ips {
        for (local_name, ip) in networks {
            let zone_name = if node_name == own_name {
                local_name
            } else {
                consts::MESH_INTERFACE_NAME
            };

            add_tags(
                tags_map,
                IpOrNetwork::Ip(*ip),
                tags.iter().cloned(),
                zone_name,
            );
        }
    }
}

fn node_scoped_identifier(node_name: &str, identifier: &str) -> String {
    format!("{node_name}.{identifier}")
}

fn add_zones_tags(node_name: &str, node: &Node, tags_map: &mut HashMap<String, TagResolution>) {
    for (zone_name, zone) in &node.zones {
        let Some(address) = zone.address else {
            continue;
        };

        let zone_tags = iter::once(node_scoped_identifier(node_name, zone_name))
            .chain(zone.tags.iter().cloned());
        add_tags(
            tags_map,
            IpOrNetwork::Network(address.network()),
            zone_tags,
            zone_name,
        );

        for (device_name, device) in &zone.devices {
            let device_tags = iter::once(node_scoped_identifier(node_name, device_name))
                .chain(device.tags.iter().cloned());
            add_tags(tags_map, IpOrNetwork::Ip(device.ip), device_tags, zone_name);
        }
    }
}

fn add_vpn_interfaces_tags(
    node_name: &str,
    node: &Node,
    tags_map: &mut HashMap<String, TagResolution>,
) {
    for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
        let vpn_interface_tags = iter::once(node_scoped_identifier(node_name, vpn_interface_name))
            .chain(vpn_interface.tags.iter().cloned());
        add_tags(
            tags_map,
            IpOrNetwork::Network(vpn_interface.address.network()),
            vpn_interface_tags,
            vpn_interface_name,
        );

        for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
            let vpn_interface_client_tags =
                iter::once(node_scoped_identifier(node_name, vpn_interface_client_name))
                    .chain(vpn_interface_client.tags.iter().cloned());

            add_tags(
                tags_map,
                IpOrNetwork::Ip(vpn_interface_client.ip),
                vpn_interface_client_tags,
                vpn_interface_name,
            );
        }
    }
}

pub fn build_tags_resolution_map(
    config: &Config,
    own_name: &str,
) -> HashMap<String, TagResolution> {
    let mut tags_map: HashMap<String, TagResolution> = HashMap::new();

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
