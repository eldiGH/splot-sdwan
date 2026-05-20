use std::net::Ipv4Addr;

use crate::{
    config::{Config, Service, ZoneOrVpnInterface},
    managers::{UciSectionBuilder, firewall::consts::FIREWALL_FILE_NAME},
    naming,
    protocol::Protocols,
    types::{
        identifier::{Identifier, NestedIdentifier},
        port::PortOrRange,
        wan_via_target::WanViaTarget,
    },
    uci::UciBatchCommand,
};

pub struct FirewallRedirect {
    pub name: String,
    pub proto: Protocols,
    pub src: String,
    pub src_dport: PortOrRange,
    pub dest_ip: Ipv4Addr,
    pub dest_port: PortOrRange,
}

impl FirewallRedirect {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "redirect")
            .set("name", naming::name_prefixed(&self.name))
            .set("target", "DNAT")
            .set("src", &self.src)
            .set("src_dport", self.src_dport.to_string())
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", self.dest_port.to_string())
            .extend_list("proto", self.proto.iter().map(|proto| proto.to_string()))
            .build()
    }
}

fn get_local_service_redirect(
    service_name: &Identifier,
    service: &Service,
    src_zone: &Identifier,
    dest_ip: Ipv4Addr,
    own_name: &Identifier,
    owner_name: &Identifier,
    node_name: &Identifier,
) -> Option<FirewallRedirect> {
    let wan = service.wan.as_ref()?;

    if !wan
        .via
        .iter()
        .any(|via| matches!(via, WanViaTarget::Bare(node) if node == own_name))
    {
        return None;
    }

    let name = if node_name == owner_name {
        format!("{owner_name}_{service_name}_redirect")
    } else {
        format!("{node_name}_{owner_name}_{service_name}_redirect")
    };

    Some(FirewallRedirect {
        name,
        dest_ip,
        dest_port: service.port.internal(),
        proto: service.proto.clone().into(),
        src: src_zone.to_string(),
        src_dport: service.port.external(),
    })
}

fn get_local_redirects(
    config: &Config,
    own_name: &Identifier,
    wan_zone: &Identifier,
    redirects: &mut Vec<FirewallRedirect>,
) {
    for (node_name, node) in &config.nodes {
        for (service_name, service) in &node.services {
            redirects.extend(get_local_service_redirect(
                service_name,
                service,
                wan_zone,
                node.mesh_ip,
                own_name,
                node_name,
                node_name,
            ))
        }

        for zone in node.zones.values() {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    redirects.extend(get_local_service_redirect(
                        service_name,
                        service,
                        wan_zone,
                        device.ip,
                        own_name,
                        device_name,
                        node_name,
                    ));
                }
            }
        }

        for vpn_interface in node.vpn_interfaces.values() {
            for (client_name, client) in &vpn_interface.clients {
                for (service_name, service) in &client.services {
                    redirects.extend(get_local_service_redirect(
                        service_name,
                        service,
                        wan_zone,
                        client.ip,
                        own_name,
                        client_name,
                        node_name,
                    ))
                }
            }
        }
    }
}

fn get_client_redirects(
    config: &Config,
    own_name: &Identifier,
    wan_zone: &Identifier,
    redirects: &mut Vec<FirewallRedirect>,
) {
    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    for (client_name, client) in &config.clients {
        let Some(networks) = client.ips.get(own_name) else {
            continue;
        };

        let mut vpn_interface_ip: Option<Ipv4Addr> = None;
        let mut lan_zone_ip: Option<Ipv4Addr> = None;

        for (network_name, ip) in networks {
            let Some(network) = node.network_by_name(network_name) else {
                continue;
            };

            match network {
                ZoneOrVpnInterface::Zone(_) => {
                    if lan_zone_ip.is_none() {
                        lan_zone_ip = Some(*ip);
                    }
                }

                ZoneOrVpnInterface::VpnInterface(_) => {
                    if vpn_interface_ip.is_none() {
                        vpn_interface_ip = Some(*ip);
                    }
                }
            }

            if vpn_interface_ip.is_some() && lan_zone_ip.is_some() {
                break;
            }
        }

        for (service_name, service) in &client.services {
            let Some(wan) = service.wan.as_ref() else {
                continue;
            };

            let Some(dest_ip) = wan.via.iter().find_map(|via| match via {
                WanViaTarget::Bare(node) if node == own_name => {
                    client.mesh_ip.or(lan_zone_ip).or(vpn_interface_ip)
                }
                WanViaTarget::Qualified(NestedIdentifier { node, local }) if node == own_name => {
                    client.ips.get(own_name)?.get(local).copied()
                }
                _ => None,
            }) else {
                continue;
            };

            redirects.push(FirewallRedirect {
                name: format!("{client_name}_{service_name}_redirect"),
                proto: service.proto.clone().into(),
                src: wan_zone.to_string(),
                src_dport: service.port.external(),
                dest_ip,
                dest_port: service.port.internal(),
            })
        }
    }
}

pub fn get_firewall_redirects(config: &Config, own_name: &Identifier) -> Vec<FirewallRedirect> {
    let mut redirects: Vec<FirewallRedirect> = vec![];

    let Some(wan_zone) = config
        .nodes
        .get(own_name)
        .and_then(|node| node.wan_zone.as_ref())
    else {
        return redirects;
    };

    get_local_redirects(config, own_name, wan_zone, &mut redirects);
    get_client_redirects(config, own_name, wan_zone, &mut redirects);

    redirects
}
