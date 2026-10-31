//! The node's DHCP: static leases on its zones, and the routes through the node
//! on a zone whose gateway is another box.

use std::{collections::BTreeSet, fmt, iter, net::Ipv4Addr};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
        node::{Node, Zone},
    },
    types::{dns::DnsLabel, identifier::Identifier, ip::Ipv4Network, mac::MacAddress},
};

#[derive(Debug)]
pub struct DhcpPlan {
    pub leases: Vec<Lease>,
    pub routes: Vec<ZoneRoutes>,
}

/// What the node's DHCP hands out on a zone whose gateway is another box
/// (option 121, RFC 3442): the default route through that gateway, and a route
/// through the node to each network it routes, over the mesh or to its own
/// zones. A client given these ignores the router option, so the default
/// route goes with them. Without them, a host there would answer the mesh
/// through the gateway, which drops what the node let in.
#[derive(Debug)]
pub struct ZoneRoutes {
    pub zone: Identifier,
    pub gateway: Ipv4Addr,
    /// The node's address on the zone.
    pub via: Ipv4Addr,
    /// None covered by another.
    pub networks: BTreeSet<Ipv4Network>,
}

/// A static lease: the host's IP on one of this node's zones, for its MACs,
/// and the host name it's handed: the host's own name.
#[derive(Debug)]
pub struct Lease {
    pub host: HostRef,
    pub hostname: DnsLabel,
    pub ip: Ipv4Addr,
    pub macs: BTreeSet<MacAddress>,
}

/// A lease for each address a host with MACs has on this node's zones: the
/// node's devices, and global clients on its zones.
pub(super) fn plan(network: &Network, own: &Node) -> DhcpPlan {
    let leases = network
        .hosts()
        .iter()
        .filter(|host| !host.macs().is_empty())
        .flat_map(|host| {
            host.addresses()
                .iter()
                .filter(|address| {
                    matches!(address.place(), Place::Zone { node, .. } if node == own.name())
                })
                .map(|address| Lease {
                    host: host.id().clone(),
                    hostname: host
                        .id()
                        .name()
                        .as_ref()
                        .parse()
                        .expect("checked: a host splot leases an address to is named as a host"),
                    ip: address.ip(),
                    macs: host.macs().clone(),
                })
        })
        .collect();

    DhcpPlan {
        leases,
        routes: routes(network, own),
    }
}

/// The routes through the node on each of its zones whose gateway is another
/// box: to the mesh, to what's behind the other nodes, and to its zones it's
/// the gateway of.
fn routes(network: &Network, own: &Node) -> Vec<ZoneRoutes> {
    let through_node: Vec<Ipv4Network> = iter::once(own.mesh_address().network())
        .chain(
            network
                .nodes()
                .filter(|node| node.name() != own.name())
                .flat_map(Node::networks),
        )
        .chain(
            own.zones()
                .values()
                .filter(|zone| zone.gateway().is_none())
                .map(Zone::network),
        )
        .collect();
    let networks: BTreeSet<Ipv4Network> = through_node
        .iter()
        .filter(|network| {
            !through_node
                .iter()
                .any(|other| other != *network && other.contains_network(**network))
        })
        .copied()
        .collect();

    own.zones()
        .iter()
        .filter_map(|(name, zone)| {
            Some(ZoneRoutes {
                zone: name.clone(),
                gateway: zone.gateway()?,
                via: zone.address().ip(),
                networks: networks.clone(),
            })
        })
        .collect()
}

impl fmt::Display for DhcpPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for Lease {
            host,
            hostname,
            ip,
            macs,
        } in &self.leases
        {
            writeln!(
                f,
                "lease {host} as {hostname}: {ip} for {}",
                super::list(macs)
            )?;
        }
        for ZoneRoutes {
            zone,
            gateway,
            via,
            networks,
        } in &self.routes
        {
            writeln!(
                f,
                "routes on {zone}: default via {gateway}, {} via {via}",
                super::list(networks)
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:01
clients:
  Phone:
    macs: BB:CC:DD:EE:FF:00
    ips:
      Home:
        lan: 192.168.1.60
      Cabin:
        lan: 192.168.2.60
  MeshOnly:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.0.100
";

    /// Home's leases, one line each.
    fn leases() -> Vec<String> {
        let network = checked(FIXTURE);
        let plan = plan(&network, network.node(&"Home".parse().unwrap()).unwrap());
        plan.to_string().lines().map(str::to_owned).collect()
    }

    #[test]
    fn devices_and_global_clients_with_macs_get_leases_on_this_nodes_zones() {
        assert_eq!(
            leases(),
            [
                "lease Home.printer as printer: 192.168.1.50 for [aa:bb:cc:dd:ee:ff]",
                "lease Phone as Phone: 192.168.1.60 for [bb:cc:dd:ee:ff:00]",
            ]
        );
        // Not: Cabin.nas and Phone's Cabin IP (Cabin's to lease), MeshOnly (no
        // zone IP).
    }

    #[test]
    fn a_zone_whose_gateway_is_another_box_routes_through_the_node_what_it_routes() {
        // Home's lan and dmz are behind another box's gateway, iot behind
        // Home's. Cabin's LAN and hub; the hub inside the mesh, which covers it.
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform: { os: linux, wireguard: wg-quick, firewall: none, dhcp: dnsmasq, dns: none, interfaces: { lan: eth0, dmz: eth1 } }
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan: { address: 192.168.1.2/24, gateway: 192.168.1.1 }
      dmz: { address: 192.168.5.2/24, gateway: 192.168.5.1 }
      iot: { address: 192.168.10.1/24 }
  Cabin:
    platform: { os: openwrt }
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan: { address: 192.168.2.1/24 }
    hub:
      network: 10.100.20.0/24
",
        );
        let routes = |node: &str| -> Vec<String> {
            let plan = plan(&network, network.node(&node.parse().unwrap()).unwrap());
            plan.to_string()
                .lines()
                .filter(|line| line.starts_with("routes"))
                .map(str::to_owned)
                .collect()
        };

        assert_eq!(
            routes("Home"),
            [
                "routes on dmz: default via 192.168.5.1, [10.100.0.0/16, 192.168.2.0/24, 192.168.10.0/24] via 192.168.5.2",
                "routes on lan: default via 192.168.1.1, [10.100.0.0/16, 192.168.2.0/24, 192.168.10.0/24] via 192.168.1.2",
            ]
        );
        // Cabin is its zone's gateway.
        assert!(routes("Cabin").is_empty());
    }
}
