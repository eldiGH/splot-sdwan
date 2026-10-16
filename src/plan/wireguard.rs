//! The node's WireGuard: its mesh interface and the peers on it.

use std::{fmt, iter, net::Ipv4Addr, num::NonZeroU16};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
        node::Node,
    },
    types::{
        ip::{Ipv4Interface, Ipv4Network},
        port::Port,
        wg_key::WgPublicKey,
    },
};

/// The keepalive a host sends its peers, every `interval` seconds (the mesh's
/// `keepaliveInterval`). Only a host behind NAT that offers services needs one:
/// it keeps the host's NAT mapping open, so whoever connects to it gets through.
/// A host that only dials out doesn't, and on a roaming device a keepalive
/// drains the battery and chases stale addresses.
fn keepalive(
    behind_nat: bool,
    offers_services: bool,
    interval: Option<NonZeroU16>,
) -> Option<NonZeroU16> {
    interval.filter(|_| behind_nat && offers_services)
}

/// The node's mesh interface. Its private key isn't here: the backend holds it.
#[derive(Debug)]
pub struct WireGuardPlan {
    pub listen_port: Port,
    /// The node's mesh IP with the mesh network's prefix.
    pub address: Ipv4Interface,
    pub peers: Vec<Peer>,
}

#[derive(Debug)]
pub struct Peer {
    /// Who the peer is: another node, a global client, or one of this node's hub
    /// clients.
    pub host: HostRef,
    pub public_key: WgPublicKey,
    pub allowed_ips: Vec<Ipv4Network>,
    /// Whether this node routes the peer's allowed IPs through the tunnel: what
    /// sits behind another node does; a client's own IP is on the mesh already.
    pub routed: bool,
    pub endpoint: Option<Endpoint>,
    /// Seconds between keepalives this node sends the peer; none when it sends
    /// none (see `keepalive`).
    pub keepalive: Option<NonZeroU16>,
}

/// Where a peer is reached.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub host: Ipv4Addr,
    pub port: Port,
}

/// A peer for every other node: its endpoint, and its mesh IP and everything
/// behind it (its hub network too, even while the hub has no clients).
fn node_peers(network: &Network, own: &Node, keepalive: Option<NonZeroU16>) -> Vec<Peer> {
    network
        .nodes()
        .filter(|node| node.name() != own.name())
        .map(|node| Peer {
            host: HostRef::Node(node.name().clone()),
            public_key: node.public_key().clone(),
            allowed_ips: iter::once(Ipv4Network::host(node.mesh_address().ip()))
                .chain(node.networks())
                .collect(),
            routed: true,
            endpoint: Some(Endpoint {
                host: node.endpoint(),
                port: node.listen_port(),
            }),
            keepalive,
        })
        .collect()
}

/// A peer for each host with a key and an address `on` picks.
fn client_peers(
    network: &Network,
    on: impl Fn(&Place) -> bool,
    keepalive: Option<NonZeroU16>,
) -> Vec<Peer> {
    network
        .hosts()
        .iter()
        .filter_map(|host| {
            let public_key = host.public_key()?;
            let address = host
                .addresses()
                .iter()
                .find(|address| on(address.place()))?;

            Some(Peer {
                host: host.id().clone(),
                public_key: public_key.clone(),
                allowed_ips: vec![Ipv4Network::host(address.ip())],
                routed: false,
                endpoint: None,
                keepalive,
            })
        })
        .collect()
}

pub(super) fn plan(network: &Network, own: &Node) -> WireGuardPlan {
    // What this node sends every peer. Every node has a public endpoint (nodes
    // behind NAT aren't supported yet), so none sends keepalives.
    let behind_nat = false;
    let keepalive = keepalive(
        behind_nat,
        network.offers_services(&HostRef::Node(own.name().clone())),
        network.keepalive_interval(),
    );

    let mut peers = node_peers(network, own, keepalive);
    // Global clients: peers on every node, by their mesh IP.
    peers.extend(client_peers(
        network,
        |place| *place == Place::Mesh,
        keepalive,
    ));
    // This node's hub clients: peers on this node only. Every other node reaches
    // them through this one, by the hub network in this node's peer entry.
    peers.extend(client_peers(
        network,
        |place| matches!(place, Place::Hub { node } if node == own.name()),
        keepalive,
    ));

    WireGuardPlan {
        listen_port: own.listen_port(),
        address: own.mesh_address(),
        peers,
    }
}

impl fmt::Display for WireGuardPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "interface: listen {}, address {}",
            self.listen_port, self.address
        )?;

        for peer in &self.peers {
            writeln!(f, "{peer}")?;
        }

        Ok(())
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer {}: key {}, allowed {}",
            self.host,
            self.public_key.as_str(),
            super::list(&self.allowed_ips)
        )?;

        if self.routed {
            write!(f, ", routed")?;
        }
        if let Some(Endpoint { host, port }) = self.endpoint {
            write!(f, ", endpoint {host}:{port}")?;
        }
        if let Some(keepalive) = self.keepalive {
            write!(f, ", keepalive {keepalive}s")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::checked, types::identifier::Identifier};

    // Home has a hub with a client; Cabin's hub is empty. Phone is a global
    // client; Laptop has a key but no mesh IP (only an IP on Cabin's lan).
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51821
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
    hub:
      network: 10.100.84.0/24
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
  Laptop:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    macs: AA:BB:CC:DD:EE:01
    ips:
      Cabin: { lan: 192.168.2.50 }
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn plan_for(yaml: &str, own: &str) -> WireGuardPlan {
        let network = checked(yaml);
        plan(&network, network.node(&id(own)).unwrap())
    }

    /// Each peer as `host: allowed IPs`.
    fn peers(plan: &WireGuardPlan) -> Vec<String> {
        plan.peers
            .iter()
            .map(|peer| format!("{}: {}", peer.host, super::super::list(&peer.allowed_ips)))
            .collect()
    }

    #[test]
    fn keepalive_only_for_a_host_behind_nat_that_offers_services() {
        // Only such a host must keep its NAT mapping open for whoever connects to
        // it; a keepalive anywhere else wakes roaming devices for nothing.
        let every_40s = NonZeroU16::new(40);
        assert_eq!(keepalive(true, true, every_40s), every_40s);
        assert_eq!(keepalive(true, false, every_40s), None);
        assert_eq!(keepalive(false, true, every_40s), None);
        assert_eq!(keepalive(false, false, every_40s), None);
    }

    #[test]
    fn without_an_interval_no_host_sends_keepalives() {
        assert_eq!(keepalive(true, true, None), None);
    }

    #[test]
    fn no_peer_entry_on_a_node_has_a_keepalive() {
        // Nodes aren't behind NAT, whatever they offer (the example's Home offers
        // ssh); and a node never keeps a roaming client's NAT open.
        let example = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/splot.example.yml"));
        for yaml in [FIXTURE, example] {
            let network = checked(yaml);
            for own in network.nodes() {
                for peer in plan(&network, own).peers {
                    assert_eq!(peer.keepalive, None, "on {}: {}", own.name(), peer.host);
                }
            }
        }
    }

    #[test]
    fn the_interface_has_the_nodes_port_and_mesh_address() {
        let plan = plan_for(FIXTURE, "Cabin");
        assert_eq!(plan.listen_port.to_string(), "51821");
        assert_eq!(plan.address.to_string(), "10.100.0.2/16");
    }

    #[test]
    fn peers_are_the_other_nodes_the_global_clients_and_the_own_hub_clients() {
        assert_eq!(
            peers(&plan_for(FIXTURE, "Home")),
            [
                "Cabin: [10.100.0.2/32, 192.168.2.0/24, 10.100.84.0/24]",
                "Phone: [10.100.1.10/32]",
                "Home.camera: [10.100.49.10/32]",
            ]
        );
        // The camera is a peer on its hub node only: Cabin routes Home's whole hub
        // network to Home.
        assert_eq!(
            peers(&plan_for(FIXTURE, "Cabin")),
            [
                "Home: [10.100.0.1/32, 10.100.49.0/24]",
                "Phone: [10.100.1.10/32]",
            ]
        );
    }

    #[test]
    fn a_node_peer_is_routed_and_has_an_endpoint_a_client_peer_neither() {
        let plan = plan_for(FIXTURE, "Home");
        let [cabin, phone, camera] = plan.peers.as_slice() else {
            panic!("expected three peers");
        };

        assert!(cabin.routed);
        let endpoint = cabin.endpoint.unwrap();
        assert_eq!(
            format!("{}:{}", endpoint.host, endpoint.port),
            "5.6.7.8:51821"
        );
        assert_eq!(
            cabin.public_key.as_str(),
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
        );

        for client in [phone, camera] {
            assert!(!client.routed, "{}", client.host);
            assert!(client.endpoint.is_none(), "{}", client.host);
        }
    }

    #[test]
    fn peer_allowed_ips_never_overlap() {
        // One address, one path: WireGuard sends to the peer with the longest
        // matching prefix and doesn't check whether that peer is alive, so two
        // peers must never claim the same address.
        let example = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/splot.example.yml"));
        for yaml in [FIXTURE, example] {
            let network = checked(yaml);
            for own_node in network.nodes() {
                let own = own_node.name();
                let plan = plan(&network, own_node);
                let claims: Vec<(&HostRef, Ipv4Network)> = plan
                    .peers
                    .iter()
                    .flat_map(|peer| peer.allowed_ips.iter().map(|ip| (&peer.host, *ip)))
                    .collect();
                assert!(!claims.is_empty(), "{own}");

                for (i, (peer, network)) in claims.iter().enumerate() {
                    for (other_peer, other) in &claims[i + 1..] {
                        assert!(
                            !network.overlap(*other),
                            "on {own}: {peer} {network} overlaps {other_peer} {other}"
                        );
                    }
                }
            }
        }
    }
}
