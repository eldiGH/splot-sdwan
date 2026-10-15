use std::net::Ipv4Addr;

use crate::{
    config::{Config, Service},
    managers::{
        NodeContext, UciSection, UciSectionBuilder, firewall::consts::FIREWALL_FILE_NAME, naming,
    },
    protocol::Protocols,
    types::{
        identifier::Identifier, ip::Ipv4Network, port::PortOrRange, wan_via_target::WanViaTarget,
        zone_ref::ZoneRef,
    },
};

pub struct FirewallRedirect {
    pub name: String,
    pub proto: Protocols,
    pub src: ZoneRef,
    pub src_dport: PortOrRange,
    pub src_ip: Vec<Ipv4Network>,
    pub dest_ip: Ipv4Addr,
    pub dest_port: PortOrRange,
    pub dest: ZoneRef,
}

impl UciSection for FirewallRedirect {
    const FILE: &'static str = FIREWALL_FILE_NAME;

    fn section_type(&self) -> &str {
        "redirect"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.name.as_str()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed(&self.name))
            .set("target", "DNAT")
            .set("src", self.src.to_string())
            .set("src_dport", self.src_dport.to_string())
            .extend_list("src_ip", &self.src_ip)
            .set("dest", self.dest.to_string())
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", self.dest_port.to_string())
            .extend_list("proto", &self.proto)
    }
}

struct RedirectBuilder<'a> {
    config: &'a Config,
    node_context: &'a NodeContext<'a>,
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

        if !wan.via.iter().any(
            |via| matches!(via, WanViaTarget::Bare(node) if node == self.node_context.own_name),
        ) {
            return None;
        }

        let name = if node_name == owner_name {
            format!("{owner_name}_{service_name}")
        } else {
            format!("{node_name}_{owner_name}_{service_name}")
        };

        Some(FirewallRedirect {
            name,
            dest: dest_zone,
            dest_ip,
            dest_port: service.port.internal(),
            proto: service.proto.clone().into(),
            src: self.wan_zone.clone(),
            src_dport: service.port.external(),
            src_ip: wan.sources.iter().cloned().collect(),
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
        }
    }

    fn client_redirects(&self, redirects: &mut Vec<FirewallRedirect>) {
        for (client_name, client) in &self.config.clients {
            for (service_name, service) in &client.services {
                let Some(wan) = &service.wan else { continue };

                for via in &wan.via {
                    if via.node() != self.node_context.own_name {
                        continue;
                    }

                    let Ok(resolution) = client.resolve_wan_target(via, self.node_context.own_node)
                    else {
                        continue;
                    };

                    let name = format!("{client_name}_{service_name}");
                    redirects.push(FirewallRedirect {
                        name,
                        proto: service.proto.clone().into(),
                        src: self.wan_zone.clone(),
                        src_dport: service.port.external(),
                        src_ip: wan.sources.iter().cloned().collect(),
                        dest: resolution.dest_zone,
                        dest_ip: resolution.dest_ip,
                        dest_port: service.port.internal(),
                    })
                }
            }
        }
    }
}

pub fn get_firewall_redirects(
    config: &Config,
    node_context: &NodeContext,
) -> Vec<FirewallRedirect> {
    let mut redirects: Vec<FirewallRedirect> = vec![];

    let Some(wan_zone) = node_context
        .own_node
        .wan_zone
        .as_ref()
        .map(|id| ZoneRef::Named(id.clone()))
    else {
        return redirects;
    };

    let builder = RedirectBuilder {
        config,
        node_context,
        wan_zone: &wan_zone,
    };

    builder.local_redirects(&mut redirects);
    builder.client_redirects(&mut redirects);

    redirects
}
