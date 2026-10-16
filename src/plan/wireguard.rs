//! The node's WireGuard: its mesh interface and the peers on it.

use std::{fmt, iter, net::Ipv4Addr};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
        node::Node,
    },
    types::{
        identifier::Identifier,
        ip::{Ipv4Interface, Ipv4Network},
        port::Port,
        wg_key::WgPublicKey,
    },
};

/// Seconds between keepalives where a peer gets them.
// TODO: the rule that decides which peers get keepalives replaces this.
const KEEPALIVE: u16 = 25;

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
    /// none.
    pub keepalive: Option<u16>,
}

/// Where a peer is reached.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub host: Ipv4Addr,
    pub port: Port,
}

/// A peer for every other node: its endpoint, and its mesh IP and everything
/// behind it (its hub network too, even while the hub has no clients).
fn node_peers(network: &Network, own_name: &Identifier) -> Vec<Peer> {
    network
        .nodes()
        .filter(|(node_name, _)| *node_name != own_name)
        .map(|(node_name, node)| Peer {
            host: HostRef::Node(node_name.clone()),
            public_key: node.public_key().clone(),
            allowed_ips: iter::once(Ipv4Network::host(node.mesh_address().ip()))
                .chain(node.networks())
                .collect(),
            routed: true,
            endpoint: Some(Endpoint {
                host: node.endpoint(),
                port: node.listen_port(),
            }),
            keepalive: Some(KEEPALIVE),
        })
        .collect()
}

/// A peer for each host with a key and an address `on` picks.
fn client_peers(network: &Network, on: impl Fn(&Place) -> bool) -> Vec<Peer> {
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
                keepalive: Some(KEEPALIVE),
            })
        })
        .collect()
}

pub(super) fn plan(network: &Network, own_name: &Identifier, own_node: &Node) -> WireGuardPlan {
    let mut peers = node_peers(network, own_name);
    // Global clients: peers on every node, by their mesh IP.
    peers.extend(client_peers(network, |place| *place == Place::Mesh));
    // This node's hub clients: peers on this node only. Every other node reaches
    // them through this one, by the hub network in this node's peer entry.
    peers.extend(client_peers(
        network,
        |place| matches!(place, Place::Hub { node } if node == own_name),
    ));

    WireGuardPlan {
        listen_port: own_node.listen_port(),
        address: own_node.mesh_address(),
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
    use crate::test_support::checked;

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
        plan(&network, &id(own), network.node(&id(own)).unwrap())
    }

    /// Each peer as `host: allowed IPs`.
    fn peers(plan: &WireGuardPlan) -> Vec<String> {
        plan.peers
            .iter()
            .map(|peer| format!("{}: {}", peer.host, super::super::list(&peer.allowed_ips)))
            .collect()
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
            for (own, own_node) in network.nodes() {
                let plan = plan(&network, own, own_node);
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
