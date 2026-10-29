//! The node's firewall: the mesh zone splot owns, the flows it lets through, and
//! the port forwards from the internet.

pub mod redirect;
pub mod rules;
pub mod zone_ref;

use std::{fmt, net::Ipv4Addr};

use super::wireguard::WireGuardPlan;
use crate::{
    model::{Network, host::HostRef, node::Node},
    types::{identifier::Identifier, port::Port},
};
use redirect::Redirect;
use rules::Rule;
use zone_ref::ZoneRef;

#[derive(Debug)]
pub struct FirewallPlan {
    /// The mesh zone: everything that arrives over WireGuard. None when splot
    /// leaves the node's WireGuard alone: the mesh then arrives on the
    /// operator's own interface, in a zone of theirs.
    pub mesh_zone: Option<ZonePolicy>,
    /// The node's WireGuard peers may ping it: none without a mesh zone.
    pub ping: Option<Ping>,
    /// None on a node nobody dials, or whose WireGuard splot leaves alone.
    pub listen_port: Option<ListenPort>,
    /// Ingress rules first, then egress.
    pub rules: Vec<Rule>,
    /// Without a mesh zone, none to a host reached over the mesh.
    pub redirects: Vec<Redirect>,
}

/// What a zone does with traffic no rule matches.
#[derive(Debug, Clone, Copy)]
pub struct ZonePolicy {
    /// To the node itself.
    pub input: Verdict,
    /// From the node.
    pub output: Verdict,
    /// Through the node, within the zone.
    pub forward: Verdict,
}

/// Every WireGuard peer of the node may ping it: an echo request from the peer's
/// own address to the node's mesh IP, to the node itself and nowhere else. The
/// health check of an apply pings the peers.
#[derive(Debug)]
pub struct Ping {
    /// The node's mesh IP.
    pub to: Ipv4Addr,
    /// Each peer, and its own address on the mesh.
    pub from: Vec<(HostRef, Ipv4Addr)>,
}

/// Others dial the node: its WireGuard listen port is let in from its WAN, to
/// the node itself. One that only dials out needs none: the replies come back
/// as established traffic.
#[derive(Debug)]
pub struct ListenPort {
    /// The node's `wanZone`.
    pub wan_zone: Identifier,
    pub port: Port,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// The firewall of `own`, whose WireGuard plan is `wireguard` (none where splot
/// leaves its WireGuard alone).
pub(super) fn plan(
    network: &Network,
    own: &Node,
    wireguard: Option<&WireGuardPlan>,
) -> FirewallPlan {
    // Access is granted only by rules.
    let mesh_zone = wireguard.map(|_| ZonePolicy {
        input: Verdict::Drop,
        output: Verdict::Accept,
        forward: Verdict::Drop,
    });
    let rules = rules::rules(network, own, mesh_zone.is_some());
    let ping = wireguard.map(|wireguard| Ping {
        to: wireguard.address.ip(),
        from: wireguard
            .peers
            .iter()
            .map(|peer| (peer.host.clone(), peer.address))
            .collect(),
    });
    let listen_port = wireguard
        .filter(|_| own.endpoint().is_some())
        .zip(own.wan_zone())
        .map(|(wireguard, wan_zone)| ListenPort {
            wan_zone: wan_zone.clone(),
            port: wireguard.listen_port,
        });
    let mut redirects = redirect::redirects(network, own);
    if mesh_zone.is_none() {
        redirects.retain(|redirect| redirect.dest_zone != ZoneRef::Mesh);
    }

    FirewallPlan {
        mesh_zone,
        ping,
        listen_port,
        rules,
        redirects,
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
        }
    }
}

impl fmt::Display for FirewallPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.mesh_zone {
            Some(ZonePolicy {
                input,
                output,
                forward,
            }) => writeln!(
                f,
                "mesh zone: input {input}, output {output}, forward {forward}"
            )?,
            None => writeln!(f, "mesh zone: none (WireGuard left alone)")?,
        }
        if let Some(Ping { to, from }) = &self.ping {
            let from = from
                .iter()
                .map(|(host, address)| format!("{host} {address}"));
            writeln!(f, "ping {to} from {}", super::list(from))?;
        }
        if let Some(ListenPort { wan_zone, port }) = &self.listen_port {
            writeln!(f, "listen port: {wan_zone} udp/{port}")?;
        }

        for rule in &self.rules {
            writeln!(f, "{rule}")?;
        }
        for redirect in &self.redirects {
            writeln!(f, "{redirect}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    // Home forwards to its printer (a zone of its own), to Phone's mesh IP and
    // to the camera on its hub; the printer takes ipp from Phone.
    const HOME: &str = "
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
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
            services:
              ipp: { port: 631, proto: tcp, allowFrom: Phone, wan: { via: Home } }
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, wan: { via: Home } }
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.1.10
    services:
      http: { port: 8080, proto: tcp, wan: { via: Home } }
";

    fn home(yaml: &str) -> FirewallPlan {
        let network = checked(yaml);
        let home = network.node(&"Home".parse().unwrap()).unwrap();
        let wireguard = home
            .platform()
            .wireguard()
            .map(|_| super::super::wireguard::plan(&network, home));
        plan(&network, home, wireguard.as_ref())
    }

    fn forwards(plan: &FirewallPlan) -> Vec<String> {
        plan.redirects
            .iter()
            .map(|redirect| format!("{} {}", redirect.host, redirect.service))
            .collect()
    }

    #[test]
    fn every_peer_may_ping_the_node_on_its_mesh_ip() {
        // Another node, a global client and Home's own hub client, each from its
        // own address. Not Cabin's hub client: it isn't Home's peer.
        let Ping { to, from } = home(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    hub:
      network: 10.100.84.0/24
      clients:
        doorbell:
          publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
          ip: 10.100.84.10
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.1.10
",
        )
        .ping
        .unwrap();

        assert_eq!(to.to_string(), "10.100.0.1");
        let from: Vec<String> = from
            .iter()
            .map(|(host, address)| format!("{host} {address}"))
            .collect();
        assert_eq!(
            from,
            [
                "Cabin 10.100.0.2",
                "Phone 10.100.1.10",
                "Home.camera 10.100.49.10"
            ]
        );
    }

    #[test]
    fn a_node_others_dial_lets_its_listen_port_in_from_its_wan() {
        let ListenPort { wan_zone, port } = home(HOME).listen_port.unwrap();
        assert_eq!(wan_zone.as_ref(), "wan");
        assert_eq!(port.to_string(), "51820");
    }

    #[test]
    fn a_node_nobody_dials_opens_no_port() {
        // It dials out, and the replies come back as established traffic. Its
        // hub would need an endpoint.
        let hub_start = HOME.find("    hub:\n").unwrap();
        let hub_end = HOME.find("clients:\n  Phone").unwrap();
        let undialled = format!("{}{}", &HOME[..hub_start], &HOME[hub_end..])
            .replace("    endpoint: 1.2.3.4\n", "");
        let plan = home(&undialled);
        assert!(plan.listen_port.is_none());
        assert!(!plan.to_string().contains("listen port"));
    }

    #[test]
    fn with_splots_wireguard_the_mesh_has_its_zone_and_its_forwards() {
        let plan = home(HOME);
        assert!(plan.mesh_zone.is_some());
        assert_eq!(
            forwards(&plan),
            ["Home.printer ipp", "Home.camera rtsp", "Phone http"]
        );
    }

    #[test]
    fn without_splots_wireguard_nothing_points_into_the_mesh() {
        // The mesh arrives on the operator's own interface, in a zone of theirs
        // that splot doesn't know: no mesh zone, no forward to a host reached
        // over the mesh, no rule for what comes over it. The rest stays. Such a
        // node has no hub.
        let hub_start = HOME.find("    hub:\n").unwrap();
        let hub_end = HOME.find("clients:\n  Phone").unwrap();
        let without_hub = format!("{}{}", &HOME[..hub_start], &HOME[hub_end..]);
        let plan = home(&without_hub.replace(
            "      os: openwrt\n",
            "      os: openwrt\n      wireguard: none\n",
        ));
        assert!(plan.mesh_zone.is_none());
        assert!(plan.ping.is_none());
        // The operator's interface listens there, not splot's.
        assert!(plan.listen_port.is_none());
        assert_eq!(forwards(&plan), ["Home.printer ipp"]);
        // Phone reaches the printer over the mesh.
        assert!(plan.rules.is_empty(), "{:?}", plan.rules);
        assert!(plan.to_string().contains("mesh zone: none"));
    }
}
