use std::collections::{HashMap, HashSet};

use crate::{
    config::{Config, Service},
    managers::{
        UciSectionBuilder,
        firewall::{
            consts::FIREWALL_FILE_NAME,
            types::{FirewallAction, IpOrNetwork, TagResolution},
        },
    },
    naming,
    protocol::Protocol,
    types::ip::Ipv4Interface,
    uci::UciBatchCommand,
};

pub struct FirewallRule {
    pub name: String,
    pub src_ip: Vec<IpOrNetwork>,
    pub proto: HashSet<Protocol>,
    pub dest_port: String,
    pub dest_ip: Vec<Ipv4Interface>,
    pub target: FirewallAction,
}

impl FirewallRule {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "rule")
            .set("name", naming::name_prefixed(&self.name))
            .set("src", "*")
            .set("dest", "*")
            .set("dest_port", &self.dest_port)
            .set("target", self.target.to_string())
            .extend_list("dest_ip", self.dest_ip.iter().map(|ip| ip.to_string()))
            .extend_list("src_ip", self.src_ip.iter().map(|ip| ip.to_string()))
            .extend_list("proto", self.proto.iter().map(|proto| proto.to_string()))
            .build()
    }
}

fn generate_rule_from_service(
    service: &Service,
    dest_addresses: impl IntoIterator<Item = Ipv4Interface>,
    name: &str,
    owner_name: &str,
    tag_resolutions: &HashMap<String, TagResolution>,
) -> Option<FirewallRule> {
    let dest_addresses: Vec<Ipv4Interface> = dest_addresses.into_iter().collect();

    let src_ip: Vec<IpOrNetwork> = service
        .allow_from
        .iter()
        .flat_map(|tag| {
            tag_resolutions
                .get(tag)
                .expect("allowFrom tag not found in resolution map")
                .values()
                .flatten()
                // skip same-LAN sources — they don't traverse this router's firewall
                .filter(|resolution| match resolution {
                    IpOrNetwork::Ip(ip) => !dest_addresses
                        .iter()
                        .all(|dest_address| dest_address.is_in_same_network(*ip)),
                    IpOrNetwork::Network(network) => !dest_addresses
                        .iter()
                        .all(|dest_address| dest_address.is_in_same_network(network.ip())),
                })
        })
        .cloned()
        .collect();

    if src_ip.is_empty() {
        return None;
    }

    let rule_name = format!("{}_{}", owner_name, name);

    Some(FirewallRule {
        src_ip,
        name: rule_name,
        dest_ip: dest_addresses,
        dest_port: service.port.clone(),
        proto: service.proto.clone().into(),
        target: FirewallAction::Accept,
    })
}

pub fn get_firewall_ingress_rules(
    config: &Config,
    own_name: &str,
    tags: &HashMap<String, TagResolution>,
) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = Vec::new();

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    let node_ips = node.zones.values().filter_map(|zone| zone.address).chain(
        node.vpn_interfaces
            .values()
            .map(|vpn_interface| vpn_interface.address),
    );

    for (service_name, service) in &node.services {
        rules.extend(generate_rule_from_service(
            service,
            node_ips.clone(),
            service_name,
            own_name,
            tags,
        ));
    }

    for zone in node.zones.values() {
        let Some(zone_address) = zone.address else {
            continue;
        };

        for (device_name, device) in &zone.devices {
            for (service_name, service) in &device.services {
                rules.extend(generate_rule_from_service(
                    service,
                    [Ipv4Interface::from_ip(device.ip, zone_address.prefix())
                        .expect("Invalid addresses should be validated before running manager")],
                    service_name,
                    device_name,
                    tags,
                ));
            }
        }
    }

    for interface in node.vpn_interfaces.values() {
        for (client_name, client) in &interface.clients {
            for (service_name, service) in &client.services {
                rules.extend(generate_rule_from_service(
                    service,
                    [
                        Ipv4Interface::from_ip(client.ip, interface.address.prefix())
                            .expect("Invalid addresses should be validated before running manager"),
                    ],
                    service_name,
                    client_name,
                    tags,
                ));
            }
        }
    }

    for (client_name, client) in &config.clients {
        let Some(networks) = client.ips.get(own_name) else {
            continue;
        };

        let ips: Vec<Ipv4Interface> = networks
            .iter()
            .filter_map(|(network_name, ip)| {
                let network_address = node.network_by_name(network_name)?.address()?;

                Some(
                    Ipv4Interface::from_ip(*ip, network_address.prefix())
                        .expect("ip and prefix should be validated at this point."),
                )
            })
            .collect();

        for (service_name, service) in &client.services {
            rules.extend(generate_rule_from_service(
                service,
                ips.iter().cloned(),
                service_name,
                client_name,
                tags,
            ));
        }
    }

    rules
}
