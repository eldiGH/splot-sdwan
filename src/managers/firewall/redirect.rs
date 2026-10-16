use std::net::Ipv4Addr;

use crate::{
    managers::{
        NodeContext, UciSection, UciSectionBuilder, firewall::consts::FIREWALL_FILE_NAME, naming,
    },
    model::{
        Network,
        host::{HostRef, Place},
    },
    protocol::Protocols,
    types::{ip::Ipv4Network, port::PortOrRange, zone_ref::ZoneRef},
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

/// The zone a target is in, on the node that forwards to it. Everything on the
/// mesh or a hub arrives through the mesh zone. A zone is named as on its own
/// node, which is right only when that node is this one.
fn dest_zone(place: &Place) -> ZoneRef {
    match place {
        Place::Zone { zone, .. } => ZoneRef::Named(zone.clone()),
        Place::Hub { .. } | Place::Mesh => ZoneRef::Mesh,
    }
}

/// The host part of a redirect's name: a host inside a node with the node's name.
fn owner_name(host: &HostRef) -> String {
    match host {
        HostRef::Local { node, name } => format!("{node}_{name}"),
        _ => host.name().to_string(),
    }
}

/// A redirect for every service exposed through this node, to what it forwards
/// the service to. None when the node has no `wanZone`.
pub fn get_firewall_redirects(
    network: &Network,
    node_context: &NodeContext,
) -> Vec<FirewallRedirect> {
    let Some(wan_zone) = &node_context.own_node.wan_zone else {
        return Vec::new();
    };
    let mut redirects = Vec::new();

    for host in network.hosts() {
        for (service_name, service) in host.services() {
            let Some(wan) = service.wan() else { continue };
            let Some(target) = wan.target(node_context.own_name) else {
                continue;
            };

            redirects.push(FirewallRedirect {
                name: format!("{}_{service_name}", owner_name(host.id())),
                proto: service.proto().clone().into(),
                src: ZoneRef::Named(wan_zone.clone()),
                src_dport: service.port().external(),
                src_ip: wan.sources().iter().copied().collect(),
                dest: dest_zone(target.place()),
                dest_ip: target.ip(),
                dest_port: service.port().internal(),
            });
        }
    }

    redirects
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{splot_config::SplotConfig, test_support::checked, types::identifier::Identifier};

    fn redirects(yaml: &str, own: &str) -> Vec<FirewallRedirect> {
        let (cfg, network) = checked(yaml);
        let own_name: Identifier = own.parse().unwrap();
        let splot_config = SplotConfig::for_tests("AAAA");

        get_firewall_redirects(
            &network,
            &NodeContext {
                own_node: cfg.nodes.get(&own_name).unwrap(),
                own_name: &own_name,
                splot_config: &splot_config,
            },
        )
    }

    #[test]
    fn hub_client_service_is_forwarded_into_the_mesh() {
        let redirects = redirects(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            http: { port: '8080:80', proto: tcp, wan: { via: Home } }
",
            "Home",
        );
        let [redirect] = redirects.as_slice() else {
            panic!("expected one redirect, got {}", redirects.len());
        };
        assert_eq!(redirect.name, "Home_camera_http");
        assert_eq!(redirect.dest, ZoneRef::Mesh);
        assert_eq!(redirect.dest_ip.to_string(), "10.100.49.10");
        assert_eq!(redirect.src_dport.to_string(), "8080");
        assert_eq!(redirect.dest_port.to_string(), "80");
    }

    // Home and Cabin both have a WAN. Home exposes its own ssh, Cabin its nas's
    // https. Phone (with a mesh IP) and Laptop (only an IP on Home's lan) are
    // exposed through Home.
    const EXPOSED: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      ssh: { port: '2222:22', proto: tcp, wan: { via: Home } }
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas:
            ip: 192.168.2.20
            macs: AA:BB:CC:DD:EE:01
            services:
              https: { port: 443, proto: tcp, wan: { via: Cabin } }
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.1.10
    services:
      web: { port: 8080, proto: tcp, wan: { via: Home } }
  Laptop:
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home: { lan: 192.168.1.50 }
    services:
      game: { port: 27015, proto: udp, wan: { via: Home } }
";

    /// Each redirect as `name -> dest_zone dest_ip`.
    fn targets(redirects: &[FirewallRedirect]) -> Vec<String> {
        redirects
            .iter()
            .map(|r| format!("{} -> {} {}", r.name, r.dest, r.dest_ip))
            .collect()
    }

    #[test]
    fn only_services_exposed_through_this_node_are_forwarded() {
        assert_eq!(
            targets(&redirects(EXPOSED, "Home")),
            [
                "Home_ssh -> mesh 10.100.0.1",
                "Laptop_game -> lan 192.168.1.50",
                "Phone_web -> mesh 10.100.1.10",
            ]
        );
        assert_eq!(
            targets(&redirects(EXPOSED, "Cabin")),
            ["Cabin_nas_https -> lan 192.168.2.20"]
        );
    }
}
