//! The node's firewall: the mesh zone splot owns, the flows it lets through, and
//! the port forwards from the internet.

pub mod redirect;
pub mod rules;
pub mod zone_ref;

use std::fmt;

use crate::model::{Network, node::Node};
use redirect::Redirect;
use rules::Rule;
use zone_ref::ZoneRef;

#[derive(Debug)]
pub struct FirewallPlan {
    /// The mesh zone: everything that arrives over WireGuard. None when splot
    /// leaves the node's WireGuard alone: the mesh then arrives on the
    /// operator's own interface, in a zone of theirs.
    pub mesh_zone: Option<ZonePolicy>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

pub(super) fn plan(network: &Network, own: &Node) -> FirewallPlan {
    let mut rules = rules::ingress_rules(network, own);
    rules.extend(rules::egress_rules(network, own));

    // Access is granted only by rules.
    let mesh_zone = own.platform().wireguard().map(|_| ZonePolicy {
        input: Verdict::Drop,
        output: Verdict::Accept,
        forward: Verdict::Drop,
    });
    let mut redirects = redirect::redirects(network, own);
    if mesh_zone.is_none() {
        redirects.retain(|redirect| redirect.dest_zone != ZoneRef::Mesh);
    }

    FirewallPlan {
        mesh_zone,
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
        plan(&network, network.node(&"Home".parse().unwrap()).unwrap())
    }

    fn forwards(plan: &FirewallPlan) -> Vec<String> {
        plan.redirects
            .iter()
            .map(|redirect| format!("{} {}", redirect.host, redirect.service))
            .collect()
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
        // over the mesh. The rest stays. Such a node has no hub.
        let hub_start = HOME.find("    hub:\n").unwrap();
        let hub_end = HOME.find("clients:\n  Phone").unwrap();
        let without_hub = format!("{}{}", &HOME[..hub_start], &HOME[hub_end..]);
        let plan = home(&without_hub.replace(
            "      os: openwrt\n",
            "      os: openwrt\n      wireguard: none\n",
        ));
        assert!(plan.mesh_zone.is_none());
        assert_eq!(forwards(&plan), ["Home.printer ipp"]);

        let rules: Vec<String> = plan
            .rules
            .iter()
            .map(|rule| format!("{} {}", rule.host, rule.service))
            .collect();
        assert_eq!(rules, ["Home.printer ipp"]);
        assert!(plan.to_string().contains("mesh zone: none"));
    }
}
