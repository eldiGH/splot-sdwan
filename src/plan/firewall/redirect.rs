//! Redirects: port forwards from the internet to the services exposed through
//! this node.

use std::{collections::BTreeSet, fmt, net::Ipv4Addr};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
        node::Node,
    },
    protocol::Protocol,
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange, zone_ref::ZoneRef},
};

/// A port forward from the internet, through this node, to one service of one
/// host.
#[derive(Debug)]
pub struct Redirect {
    pub host: HostRef,
    pub service: Identifier,
    /// The firewall zone the internet comes in through: the node's `wanZone`.
    pub wan_zone: Identifier,
    pub external_port: PortOrRange,
    /// The CIDRs the internet side may come from; none means anyone.
    pub sources: Vec<Ipv4Network>,
    pub dest_zone: ZoneRef,
    pub dest_ip: Ipv4Addr,
    pub internal_port: PortOrRange,
    pub proto: BTreeSet<Protocol>,
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

/// A redirect for every service exposed through this node, to what it forwards
/// the service to. None when the node has no `wanZone`.
pub(super) fn redirects(network: &Network, own: &Node) -> Vec<Redirect> {
    let Some(wan_zone) = own.wan_zone() else {
        return Vec::new();
    };
    let mut redirects = Vec::new();

    for host in network.hosts() {
        for (service_name, service) in network.services_of(host) {
            let Some(wan) = service.wan() else { continue };
            let Some(target) = wan.target(own.name()) else {
                continue;
            };

            redirects.push(Redirect {
                host: host.id().clone(),
                service: service_name.clone(),
                wan_zone: wan_zone.clone(),
                external_port: service.port().external(),
                sources: wan.sources().iter().copied().collect(),
                dest_zone: dest_zone(target.place()),
                dest_ip: target.ip(),
                internal_port: service.port().internal(),
                proto: service.proto().clone(),
            });
        }
    }

    redirects
}

impl fmt::Display for Redirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "forward {} {}: {} {} from {} to {} {}:{}",
            self.host,
            self.service,
            self.wan_zone,
            super::super::proto_port(&self.proto, &self.external_port),
            super::super::list(&self.sources),
            self.dest_zone,
            self.dest_ip,
            self.internal_port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    fn redirects(yaml: &str, own: &str) -> Vec<Redirect> {
        let network = checked(yaml);
        let own_name: Identifier = own.parse().unwrap();

        super::redirects(&network, network.node(&own_name).unwrap())
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
        assert_eq!(redirect.host.to_string(), "Home.camera");
        assert_eq!(redirect.service.as_ref(), "http");
        assert_eq!(redirect.wan_zone.as_ref(), "wan");
        assert_eq!(redirect.dest_zone, ZoneRef::Mesh);
        assert_eq!(redirect.dest_ip.to_string(), "10.100.49.10");
        assert_eq!(redirect.external_port.to_string(), "8080");
        assert_eq!(redirect.internal_port.to_string(), "80");
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

    /// Each redirect as `host service -> dest_zone dest_ip`.
    fn targets(redirects: &[Redirect]) -> Vec<String> {
        redirects
            .iter()
            .map(|r| format!("{} {} -> {} {}", r.host, r.service, r.dest_zone, r.dest_ip))
            .collect()
    }

    #[test]
    fn only_services_exposed_through_this_node_are_forwarded() {
        assert_eq!(
            targets(&redirects(EXPOSED, "Home")),
            [
                "Home ssh -> mesh 10.100.0.1",
                "Laptop game -> lan 192.168.1.50",
                "Phone web -> mesh 10.100.1.10",
            ]
        );
        assert_eq!(
            targets(&redirects(EXPOSED, "Cabin")),
            ["Cabin.nas https -> lan 192.168.2.20"]
        );
    }
}
