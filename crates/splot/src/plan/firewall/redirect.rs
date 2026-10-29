//! Redirects: port forwards from the internet to the services exposed through
//! this node.

use std::{collections::BTreeSet, fmt, net::Ipv4Addr};

use crate::{
    model::{Network, host::HostRef, node::Node},
    plan::{firewall::zone_ref::ZoneRef, list, proto_port},
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange, protocol::Protocol},
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
    /// The address the forward leaves as when it goes into the mesh to another
    /// host: the node's mesh IP. WireGuard takes from a peer only that peer's own
    /// addresses, and the host would answer the internet by its own route; from
    /// the mesh IP, the host's node lets it in, and the replies come back through
    /// this node. None to a host in one of the node's zones, or to the node
    /// itself.
    pub snat: Option<Ipv4Addr>,
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
            let dest_zone = ZoneRef::on(own.name(), target.place());
            let itself = matches!(host.id(), HostRef::Node(node) if node == own.name());
            let snat = (dest_zone == ZoneRef::Mesh && !itself).then(|| own.mesh_address().ip());

            redirects.push(Redirect {
                host: host.id().clone(),
                service: service_name.clone(),
                wan_zone: wan_zone.clone(),
                external_port: service.port().external(),
                sources: wan.sources().iter().copied().collect(),
                dest_zone,
                dest_ip: target.ip(),
                internal_port: service.port().internal(),
                proto: service.proto().clone(),
                snat,
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
            proto_port(&self.proto, &self.external_port),
            list(&self.sources),
            self.dest_zone,
            self.dest_ip,
            self.internal_port
        )?;
        if let Some(snat) = self.snat {
            write!(f, " as {snat}")?;
        }
        Ok(())
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
    platform:
      os: openwrt
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
        // The camera is a peer of Home's: it answers through its tunnel only
        // what comes from the mesh.
        assert_eq!(redirect.snat.unwrap().to_string(), "10.100.0.1");
    }

    // Home and Cabin both have a WAN. Home exposes its own ssh, Cabin its nas's
    // https. Phone (with a mesh IP) and Laptop (only an IP on Home's lan) are
    // exposed through Home.
    const EXPOSED: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
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
    platform:
      os: openwrt
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

    /// Each redirect as `host service`, and the address it leaves as.
    fn snats(redirects: &[Redirect]) -> Vec<String> {
        redirects
            .iter()
            .map(|r| match r.snat {
                Some(snat) => format!("{} {} as {snat}", r.host, r.service),
                None => format!("{} {}", r.host, r.service),
            })
            .collect()
    }

    #[test]
    fn a_forward_into_the_mesh_to_another_host_leaves_as_the_nodes_mesh_ip() {
        // Cabin's nas and Phone's mesh IP are reached over the mesh: the replies
        // must come back through Home. Home's own ssh and Laptop on its lan are
        // Home's to reach.
        let exposed = EXPOSED.replace("wan: { via: Cabin }", "wan: { via: [Cabin, Home] }");
        assert_eq!(
            snats(&redirects(&exposed, "Home")),
            [
                "Cabin.nas https as 10.100.0.1",
                "Home ssh",
                "Laptop game",
                "Phone web as 10.100.0.1",
            ]
        );
        assert_eq!(snats(&redirects(&exposed, "Cabin")), ["Cabin.nas https"]);
    }

    #[test]
    fn a_device_behind_another_node_is_forwarded_into_the_mesh() {
        // Home reaches Cabin's nas over the mesh, though Home has a lan too.
        let exposed = EXPOSED.replace("wan: { via: Cabin }", "wan: { via: [Cabin, Home] }");
        let home = targets(&redirects(&exposed, "Home"));
        assert!(
            home.contains(&"Cabin.nas https -> mesh 192.168.2.20".to_owned()),
            "{home:?}"
        );
        assert_eq!(
            targets(&redirects(&exposed, "Cabin")),
            ["Cabin.nas https -> lan 192.168.2.20"]
        );
    }
}
