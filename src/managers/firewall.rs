use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    net::Ipv4Addr,
};

use crate::{
    config::{Config, NodeService},
    consts,
    managers::UciManager,
    naming,
    protocols::Protocols,
    types::ip::IpSubnet,
    uci::UciBatchCommand,
};

enum FirewallAction {
    Accept,
    Reject,
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "ACCEPT"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

struct FirewallRule {
    name: String,
    src_ip: Vec<String>,
    proto: HashSet<Protocols>,
    dest_port: String,
    dest_ip: String,
    target: FirewallAction,
}

struct FirewallZone {
    name: String,
    input: FirewallAction,
    output: FirewallAction,
    forward: FirewallAction,
    network: Vec<String>,
}

impl Default for FirewallZone {
    fn default() -> Self {
        Self {
            forward: FirewallAction::Reject,
            input: FirewallAction::Reject,
            output: FirewallAction::Accept,
            name: "".to_owned(),
            network: Vec::new(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum TagResolutionAddress {
    Ip(Ipv4Addr),
    Subnet(IpSubnet),
}

impl fmt::Display for TagResolutionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Subnet(subnet) => subnet.fmt(f),
        }
    }
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

        if let Some(vpn_interfaces) = &node.vpn_interfaces {
            for (interface_name, interface) in vpn_interfaces {
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

fn generate_rules_from_service(
    service: &NodeService,
    dest_address: IpSubnet,
    name: &str,
    device_name: &str,
    tag_resolutions: &HashMap<String, TagResolution>,
) -> Vec<FirewallRule> {
    service
        .allow_from
        .iter()
        .flatten()
        .map(|tag| {
            let src_ip: Vec<String> = tag_resolutions
                .get(tag)
                .expect("allowFrom tag not found in resolution map; config validation should prevent this")
                .iter()
                .filter(|resolution| match resolution {
                    TagResolutionAddress::Ip(ip) => !dest_address.contains(*ip),
                    TagResolutionAddress::Subnet(subnet) => !dest_address.contains(subnet.ip()),
                })
                .map(|resolution| resolution.to_string())
                .collect();

            if src_ip.is_empty() {
                return None;
            }

            Some(FirewallRule {
                target: FirewallAction::Accept,
                dest_port: service.port.clone(),
                dest_ip: dest_address.ip().to_string(),
                proto: service.proto.iter().copied().collect(),
                src_ip,
                name: format!("{}{}_{}", consts::SPLOT_PREFIX, device_name, name),
            })
        })
        .flatten()
        .collect()
}

fn get_firewall_rules(
    config: &Config,
    own_name: &str,
    tags: &HashMap<String, TagResolution>,
) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = Vec::new();

    let node = config.nodes.get(own_name).unwrap();

    for (service_name, service) in node.services.iter().flatten() {
        rules.extend(generate_rules_from_service(
            service,
            node.lan.address,
            service_name,
            own_name,
            tags,
        ));
    }

    for (device_name, device) in node.lan.devices.iter().flatten() {
        for (service_name, service) in device.services.iter().flatten() {
            rules.extend(generate_rules_from_service(
                service,
                IpSubnet::from_ip(device.ip, node.lan.address.prefix()).unwrap(),
                service_name,
                device_name,
                tags,
            ));
        }
    }

    for (_, interface) in node.vpn_interfaces.iter().flatten() {
        for (client_name, client) in &interface.clients {
            for (service_name, service) in client.services.iter().flatten() {
                rules.extend(generate_rules_from_service(
                    service,
                    IpSubnet::from_ip(client.ip, interface.address.prefix()).unwrap(),
                    service_name,
                    client_name,
                    tags,
                ));
            }
        }
    }

    rules
}

fn get_firewall_zones(config: &Config, own_name: &str) -> Vec<FirewallZone> {
    let mesh_interface_name = naming::mesh_interface_name().to_owned();

    let mut zones = vec![FirewallZone {
        name: mesh_interface_name.clone(),
        network: vec![mesh_interface_name],

        ..Default::default()
    }];

    let node = config.nodes.get(own_name).unwrap();

    let Some(vpn_interfaces) = &node.vpn_interfaces else {
        return zones;
    };

    zones.extend(vpn_interfaces.keys().map(|name| {
        let vpn_interface_name = naming::vpn_interface_name(name);

        FirewallZone {
            name: vpn_interface_name.clone(),
            network: vec![vpn_interface_name],
            ..Default::default()
        }
    }));

    zones
}

fn get_uci_commands(
    firewall_zones: &[FirewallZone],
    firewall_rules: &[FirewallRule],
) -> Vec<UciBatchCommand> {
    firewall_zones
        .iter()
        .flat_map(|zone| {
            let prop = |prop: &str| format!("firewall.{}.{}", zone.name, prop);

            let mut cmds = vec![
                UciBatchCommand::set(format!("firewall.{}", zone.name), "zone"),
                UciBatchCommand::set(prop("name"), &zone.name),
                UciBatchCommand::set(prop("input"), zone.input.to_string()),
                UciBatchCommand::set(prop("output"), zone.output.to_string()),
                UciBatchCommand::set(prop("forward"), zone.forward.to_string()),
            ];

            cmds.extend(
                zone.network
                    .iter()
                    .map(|network| UciBatchCommand::add_list(prop("network"), network)),
            );

            cmds
        })
        .chain(firewall_rules.iter().flat_map(|rule| {
            let prop = |prop: &str| format!("firewall.{}.{}", rule.name, prop);

            let mut cmds = vec![
                UciBatchCommand::set(format!("firewall.{}", rule.name), "rule"),
                UciBatchCommand::set(prop("name"), &rule.name),
                UciBatchCommand::set(prop("src"), "*"),
                UciBatchCommand::set(prop("dest"), "*"),
                UciBatchCommand::add_list(prop("dest_ip"), &rule.dest_ip),
                UciBatchCommand::set(prop("dest_port"), &rule.dest_port),
                UciBatchCommand::set(prop("target"), rule.target.to_string()),
            ];

            cmds.extend(
                rule.src_ip
                    .iter()
                    .map(|src_ip| UciBatchCommand::add_list(prop("src_ip"), src_ip)),
            );

            cmds.extend(
                rule.proto
                    .iter()
                    .map(|proto| UciBatchCommand::add_list(prop("proto"), proto.to_string())),
            );

            cmds
        }))
        .collect()
}

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        "firewall"
    }

    fn anonymous_prefixes(&self) -> &'static [&'static str] {
        &[]
    }

    fn named_prefixes(&self) -> &'static [&'static str] {
        &[consts::SPLOT_PREFIX]
    }

    fn generate_commands(
        &self,
        config: &Config,
        own_name: &str,
    ) -> Result<Vec<crate::uci::UciBatchCommand>, super::ManagerErrors> {
        let tags = build_tags_resolution_map(config, own_name);

        let zones = get_firewall_zones(config, own_name);
        let rules = get_firewall_rules(config, own_name, &tags);

        Ok(get_uci_commands(&zones, &rules))
    }
}
