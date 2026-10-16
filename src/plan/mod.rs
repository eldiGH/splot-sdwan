//! What one node has to do, by concern, worked out from the checked model. No
//! platform in it: each backend renders it its own way.

pub mod dhcp;
pub mod firewall;
pub mod wireguard;

use std::{collections::BTreeSet, fmt};

use crate::{
    model::Network,
    protocol::Protocol,
    types::{identifier::Identifier, port::PortOrRange},
};
use dhcp::DhcpPlan;
use firewall::FirewallPlan;
use wireguard::WireGuardPlan;

#[derive(Debug)]
pub struct NodePlan {
    pub node: Identifier,
    pub wireguard: WireGuardPlan,
    pub firewall: FirewallPlan,
    pub dhcp: DhcpPlan,
}

/// The plan for the node named `node`; none when the network has no such node.
/// The planners take the node itself, so they only ever see one of this
/// network's.
pub fn plan(network: &Network, node: &Identifier) -> Option<NodePlan> {
    let node = network.node(node)?;

    Some(NodePlan {
        node: node.name().clone(),
        wireguard: wireguard::plan(network, node),
        firewall: firewall::plan(network, node),
        dhcp: dhcp::plan(network, node),
    })
}

/// A plain-text view of everything in the plan, one object per line, in the
/// config's own notation.
impl fmt::Display for NodePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# {}", self.node)?;
        writeln!(f, "\n[wireguard]\n{}", self.wireguard)?;
        writeln!(f, "[firewall]\n{}", self.firewall)?;
        write!(f, "[dhcp]\n{}", self.dhcp)
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
    fn no_plan_for_a_node_the_network_lacks() {
        let network = checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        assert!(plan(&network, &"Attic".parse().unwrap()).is_none());
    }
}
