//! What one node has to do, by concern, worked out from the checked model. No
//! platform in it: each backend renders it its own way.

pub mod dhcp;
pub mod firewall;
pub mod wireguard;

use std::{collections::BTreeSet, fmt};

use crate::{
    model::Network,
    types::{identifier::Identifier, port::PortOrRange, protocol::Protocol, wg_key::WgPublicKey},
};
use dhcp::DhcpPlan;
use firewall::FirewallPlan;
use wireguard::WireGuardPlan;

/// A section per concern; none for a concern splot leaves alone on the node
/// (`none` in its platform).
#[derive(Debug)]
pub struct NodePlan {
    pub node: Identifier,
    /// The node's public key. Its private key isn't here: the backend holds it,
    /// and checks the two belong together before it changes anything.
    pub public_key: WgPublicKey,
    pub wireguard: Option<WireGuardPlan>,
    pub firewall: Option<FirewallPlan>,
    pub dhcp: Option<DhcpPlan>,
}

/// The plan for the node named `node`; none when the network has no such node.
/// The planners take the node itself, so they only ever see one of this
/// network's.
pub fn plan(network: &Network, node: &Identifier) -> Option<NodePlan> {
    let node = network.node(node)?;
    let platform = node.platform();

    Some(NodePlan {
        node: node.name().clone(),
        public_key: node.public_key().clone(),
        wireguard: platform.wireguard().map(|_| wireguard::plan(network, node)),
        firewall: platform.firewall().map(|_| firewall::plan(network, node)),
        dhcp: platform.dhcp().map(|_| dhcp::plan(network, node)),
    })
}

/// A plain-text view of everything in the plan, one object per line, in the
/// config's own notation.
impl fmt::Display for NodePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# {}: key {}", self.node, self.public_key.as_str())?;
        writeln!(f, "\n[wireguard]\n{}", Section(&self.wireguard))?;
        writeln!(f, "[firewall]\n{}", Section(&self.firewall))?;
        write!(f, "[dhcp]\n{}", Section(&self.dhcp))
    }
}

/// A concern's section of the plan, or what's there when splot leaves the
/// concern alone.
struct Section<'a, T>(&'a Option<T>);

impl<T: fmt::Display> fmt::Display for Section<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(section) => section.fmt(f),
            None => writeln!(f, "none: left alone"),
        }
    }
}

/// `tcp/22`, `tcp+udp/53`.
fn proto_port(proto: &BTreeSet<Protocol>, port: &PortOrRange) -> String {
    let proto: Vec<String> = proto.iter().map(ToString::to_string).collect();

    format!("{}/{port}", proto.join("+"))
}

/// `[a, b, c]`.
fn list(items: impl IntoIterator<Item = impl fmt::Display>) -> String {
    let items: Vec<String> = items.into_iter().map(|item| item.to_string()).collect();

    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    // ── Snapshot of the plan for every node of the example config ─────────
    //
    // The platform-neutral counterpart of the uci snapshot: a change to what the
    // planner decides shows up here, and how a backend renders it in its own
    // snapshot. Accept intended changes with `cargo insta review`.

    #[test]
    fn example_plan_snapshot() {
        let network = checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));

        for node in network.nodes() {
            let plan = plan(&network, node.name()).unwrap();
            insta::assert_snapshot!(format!("plan_{}", node.name()), plan.to_string());
        }
    }

    #[test]
    fn a_concern_splot_leaves_alone_has_no_section() {
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
      firewall: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    platform:
      os: openwrt
      wireguard: none
      dhcp: none
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        let plan = |node: &str| plan(&network, &node.parse().unwrap()).unwrap();

        let home = plan("Home");
        assert!(home.wireguard.is_some());
        assert!(home.firewall.is_none());
        assert!(home.dhcp.is_some());
        assert_eq!(
            home.to_string(),
            "# Home: key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[wireguard]
interface: listen 51820, address 10.100.0.1/16
peer Cabin: key CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=, allowed [10.100.0.2/32], routed, endpoint 5.6.7.8:51820, psk

[firewall]
none: left alone

[dhcp]
"
        );

        let cabin = plan("Cabin");
        assert!(cabin.wireguard.is_none());
        assert!(cabin.firewall.is_some());
        assert!(cabin.dhcp.is_none());
        assert!(cabin.to_string().ends_with("[dhcp]\nnone: left alone\n"));
        // Its key stays: it's who the plan is for.
        assert_eq!(
            cabin.public_key.as_str(),
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
        );
    }

    #[test]
    fn no_plan_for_a_node_the_network_lacks() {
        let network = checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        assert!(plan(&network, &"Attic".parse().unwrap()).is_none());
    }
}
