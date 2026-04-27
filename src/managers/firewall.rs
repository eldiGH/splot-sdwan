use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    net::Ipv4Addr,
};

use crate::{
    config::{Config, NodeService},
    consts,
    managers::{UciManager, UciSectionBuilder},
    naming,
    protocols::Protocols,
    types::ip::IpSubnet,
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "firewall";

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
    src_ip: Vec<IpOrSubnet>,
    proto: HashSet<Protocols>,
    dest_port: String,
    dest_ip: Ipv4Addr,
    target: FirewallAction,
}

impl FirewallRule {
    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FILE_NAME, &self.name, "rule")
            .set("name", naming::name_prefixed(&self.name))
            .set("src", "*")
            .set("dest", "*")
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", &self.dest_port)
            .set("target", self.target.to_string())
            .extend_list("src_ip", self.src_ip.iter().map(|ip| ip.to_string()))
            .extend_list("proto", self.proto.iter().map(|proto| proto.to_string()))
            .build()
    }
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
            name: String::new(),
            network: Vec::new(),
        }
    }
}

impl FirewallZone {
    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FILE_NAME, &self.name, "zone")
            .set("name", naming::name_prefixed(&self.name))
            .set("input", self.input.to_string())
            .set("output", self.output.to_string())
            .set("forward", self.forward.to_string())
            .extend_list("network", &self.network)
            .build()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum IpOrSubnet {
    Ip(Ipv4Addr),
    Subnet(IpSubnet),
}

impl fmt::Display for IpOrSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Subnet(subnet) => subnet.fmt(f),
        }
    }
}

type TagResolution = HashSet<IpOrSubnet>;

pub struct FirewallManager;

fn add_tags(
    tags_map: &mut HashMap<String, TagResolution>,
    address: IpOrSubnet,
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
                IpOrSubnet::Ip(node.lan.ip),
                iter::once("$node".to_owned()),
            )
        }

        let node_tags = iter::once(node_name.clone())
            .chain(node.tags.iter().flat_map(|tag| tag.iter().cloned()));
        add_tags(
            &mut tags_map,
            IpOrSubnet::Subnet(node.lan.subnet),
            node_tags,
        );

        if let Some(lan_devices) = &node.lan.devices {
            for (device_name, device) in lan_devices {
                let device_tags = iter::once(device_name.clone())
                    .chain(device.tags.iter().flat_map(|t| t.iter().cloned()));

                add_tags(&mut tags_map, IpOrSubnet::Ip(device.ip), device_tags);
            }
        }

        if let Some(vpn_interfaces) = &node.vpn_interfaces {
            for (interface_name, interface) in vpn_interfaces {
                let interface_tags = iter::once(interface_name.clone())
                    .chain(interface.tags.iter().flat_map(|i| i.iter().cloned()));

                add_tags(
                    &mut tags_map,
                    IpOrSubnet::Subnet(interface.subnet),
                    interface_tags,
                );

                for (client_name, client) in &interface.clients {
                    let client_tags = iter::once(client_name.clone())
                        .chain(client.tags.iter().flat_map(|c| c.iter().cloned()));

                    add_tags(&mut tags_map, IpOrSubnet::Ip(client.ip), client_tags);
                }
            }
        }
    }

    tags_map
}

fn generate_rule_from_service(
    service: &NodeService,
    dest_address: IpSubnet,
    name: &str,
    device_name: &str,
    tag_resolutions: &HashMap<String, TagResolution>,
) -> Option<FirewallRule> {
    let src_ip: Vec<IpOrSubnet> = service
        .allow_from
        .iter()
        .flatten()
        .flat_map(|tag| {
            tag_resolutions
                .get(tag)
                .expect("allowFrom tag not found in resolution map")
                .iter()
                .filter(|resolution| match resolution {
                    IpOrSubnet::Ip(ip) => !dest_address.contains(*ip),
                    IpOrSubnet::Subnet(subnet) => !dest_address.contains(subnet.ip()),
                })
        })
        .cloned()
        .collect();

    if src_ip.is_empty() {
        return None;
    }

    let rule_name = format!("{}_{}", device_name, name);

    Some(FirewallRule {
        src_ip,
        name: rule_name,
        dest_ip: dest_address.ip(),
        dest_port: service.port.clone(),
        proto: service.proto.clone().into(),
        target: FirewallAction::Accept,
    })
}

fn get_firewall_rules(
    config: &Config,
    own_name: &str,
    tags: &HashMap<String, TagResolution>,
) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = Vec::new();

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    for (service_name, service) in node.services.iter().flatten() {
        rules.extend(generate_rule_from_service(
            service,
            node.lan.address,
            service_name,
            own_name,
            tags,
        ));
    }

    for (device_name, device) in node.lan.devices.iter().flatten() {
        for (service_name, service) in device.services.iter().flatten() {
            rules.extend(generate_rule_from_service(
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
                rules.extend(generate_rule_from_service(
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
    let mut zones = vec![FirewallZone {
        name: consts::MESH_INTERFACE_RAW_NAME.to_owned(),
        network: vec![naming::mesh_interface()],

        ..Default::default()
    }];

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    let Some(vpn_interfaces) = &node.vpn_interfaces else {
        return zones;
    };

    zones.extend(vpn_interfaces.keys().map(|name| FirewallZone {
        name: name.clone(),
        network: vec![naming::interface(name)],
        ..Default::default()
    }));

    zones
}

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        "firewall"
    }

    fn generate_commands(&self, config: &Config, own_name: &str) -> Vec<UciBatchCommand> {
        let tags = build_tags_resolution_map(config, own_name);

        let zones = get_firewall_zones(config, own_name);
        let rules = get_firewall_rules(config, own_name, &tags);

        zones
            .iter()
            .flat_map(|zone| zone.to_uci_commands())
            .chain(rules.iter().flat_map(|rule| rule.to_uci_commands()))
            .collect()
    }
}
