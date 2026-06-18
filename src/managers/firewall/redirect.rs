use std::net::Ipv4Addr;

use crate::{
    config::{Config, Service},
    managers::{UciSectionBuilder, firewall::consts::FIREWALL_FILE_NAME},
    naming,
    protocol::Protocols,
    types::{
        identifier::Identifier, port::PortOrRange, wan_via_target::WanViaTarget, zone_ref::ZoneRef,
    },
    uci::UciBatchCommand,
};

pub struct FirewallRedirect {
    pub name: String,
    pub proto: Protocols,
    pub src: ZoneRef,
    pub src_dport: PortOrRange,
    pub dest_ip: Ipv4Addr,
    pub dest_port: PortOrRange,
    pub dest: ZoneRef,
}

impl FirewallRedirect {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "redirect")
            .set("name", naming::name_prefixed(&self.name))
            .set("target", "DNAT")
            .set("src", self.src.to_string())
            .set("src_dport", self.src_dport.to_string())
            .set("dest", self.dest.to_string())
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", self.dest_port.to_string())
            .extend_list("proto", self.proto.iter().map(|proto| proto.to_string()))
            .build()
    }
}

struct RedirectBuilder<'a> {
    config: &'a Config,
    own_name: &'a Identifier,
    wan_zone: &'a ZoneRef,
}

impl RedirectBuilder<'_> {
    fn local_service_redirect(
        &self,
        service_name: &Identifier,
        service: &Service,
        dest_zone: ZoneRef,
        dest_ip: Ipv4Addr,
        owner_name: &Identifier,
        node_name: &Identifier,
    ) -> Option<FirewallRedirect> {
        let wan = service.wan.as_ref()?;

        if !wan
            .via
            .iter()
            .any(|via| matches!(via, WanViaTarget::Bare(node) if node == self.own_name))
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
            dest: dest_zone,
            dest_ip,
            dest_port: service.port.internal(),
            proto: service.proto.clone().into(),
            src: self.wan_zone.clone(),
            src_dport: service.port.external(),
        })
    }

    fn local_redirects(&self, redirects: &mut Vec<FirewallRedirect>) {
        for (node_name, node) in &self.config.nodes {
            for (service_name, service) in &node.services {
                redirects.extend(self.local_service_redirect(
                    service_name,
                    service,
                    ZoneRef::Mesh,
                    node.mesh_ip,
                    node_name,
                    node_name,
                ))
            }

            for (zone_name, zone) in &node.zones {
                for (device_name, device) in &zone.devices {
                    for (service_name, service) in &device.services {
                        redirects.extend(self.local_service_redirect(
                            service_name,
                            service,
                            ZoneRef::Named(zone_name.clone()),
                            device.ip,
                            device_name,
                            node_name,
                        ));
                    }
                }
            }

            for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
                for (client_name, client) in &vpn_interface.clients {
                    for (service_name, service) in &client.services {
                        redirects.extend(self.local_service_redirect(
                            service_name,
                            service,
                            ZoneRef::Named(vpn_interface_name.clone()),
                            client.ip,
                            client_name,
                            node_name,
                        ))
                    }
                }
            }
        }
    }

    fn client_redirects(&self, redirects: &mut Vec<FirewallRedirect>) {
        let node = self
            .config
            .nodes
            .get(self.own_name)
            .expect("own node not found — config should be validated before calling managers");

        for (client_name, client) in &self.config.clients {
            for (service_name, service) in &client.services {
                let Some(wan) = &service.wan else { continue };

                for via in &wan.via {
                    if via.node() != self.own_name {
                        continue;
                    }

                    let Ok(resolution) = client.resolve_wan_target(via, node) else {
                        continue;
                    };

                    redirects.push(FirewallRedirect {
                        name: format!("{client_name}_{service_name}_redirect"),
                        proto: service.proto.clone().into(),
                        src: self.wan_zone.clone(),
                        src_dport: service.port.external(),
                        dest: resolution.dest_zone,
                        dest_ip: resolution.dest_ip,
                        dest_port: service.port.internal(),
                    })
                }
            }
        }
    }
}

pub fn get_firewall_redirects(config: &Config, own_name: &Identifier) -> Vec<FirewallRedirect> {
    let mut redirects: Vec<FirewallRedirect> = vec![];

    let Some(wan_zone) = config
        .nodes
        .get(own_name)
        .and_then(|node| node.wan_zone.as_ref())
        .map(|id| ZoneRef::Named(id.clone()))
    else {
        return redirects;
    };

    let builder = RedirectBuilder {
        config,
        own_name,
        wan_zone: &wan_zone,
    };

    builder.local_redirects(&mut redirects);
    builder.client_redirects(&mut redirects);

    redirects
}
