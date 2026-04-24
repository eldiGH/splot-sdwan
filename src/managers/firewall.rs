use std::{
    collections::{HashMap, HashSet},
    iter,
    net::Ipv4Addr,
};

use crate::{config::Config, managers::UciManager, protocols::Protocols, types::ip::IpSubnet};

struct FirewallRule {
    source: String,
    name: String,
    proto: HashSet<Protocols>,
    dest_port: String,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum TagResolutionAddress {
    Ip(Ipv4Addr),
    Subnet(IpSubnet),
}

type TagResolution = HashSet<TagResolutionAddress>;

pub struct FirewallManager;

fn add_tags(
    tags_map: &mut HashMap<String, TagResolution>,
    address: TagResolutionAddress,
    tags: impl IntoIterator<Item = String>,
) {
    for tag in tags {
        tags_map.entry(tag).or_default().insert(address);
    }
}

fn build_tags_resolution_map(config: &Config, own_name: &str) -> HashMap<String, TagResolution> {
    let mut tags_map: HashMap<String, TagResolution> = HashMap::new();

    for (node_name, node) in &config.nodes {
        if node_name == own_name {
            add_tags(
                &mut tags_map,
                TagResolutionAddress::Ip(node.lan.ip),
                iter::once("$node".to_owned()),
            )
        }

        let node_tags = iter::once(node_name.clone())
            .chain(node.tags.iter().flat_map(|tag| tag.iter().cloned()));
        add_tags(
            &mut tags_map,
            TagResolutionAddress::Subnet(node.lan.subnet),
            node_tags,
        );

        if let Some(lan_devices) = &node.lan.devices {
            for (device_name, device) in lan_devices {
                let device_tags = iter::once(device_name.clone())
                    .chain(device.tags.iter().flat_map(|t| t.iter().cloned()));

                add_tags(
                    &mut tags_map,
                    TagResolutionAddress::Ip(device.ip),
                    device_tags,
                );
            }
        }

        if let Some(hosted_interfaces) = &node.hosted_interfaces {
            for (interface_name, interface) in hosted_interfaces {
                let interface_tags = iter::once(interface_name.clone())
                    .chain(interface.tags.iter().flat_map(|i| i.iter().cloned()));

                add_tags(
                    &mut tags_map,
                    TagResolutionAddress::Subnet(interface.subnet),
                    interface_tags,
                );

                for (client_name, client) in &interface.clients {
                    let client_tags = iter::once(client_name.clone())
                        .chain(client.tags.iter().flat_map(|c| c.iter().cloned()));

                    add_tags(
                        &mut tags_map,
                        TagResolutionAddress::Ip(client.ip),
                        client_tags,
                    );
                }
            }
        }
    }

    tags_map
}

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        "firewall"
    }

    fn anonymous_prefixes(&self) -> &'static [&'static str] {
        &["spl_"]
    }

    fn named_prefixes(&self) -> &'static [&'static str] {
        &["spl_"]
    }

    fn generate_commands(
        &self,
        config: &Config,
        own_name: &str,
    ) -> Result<Vec<crate::uci::UciBatchCommand>, super::ManagerErrors> {
        let tags = build_tags_resolution_map(config, own_name);

        Ok(vec![])
    }
}
