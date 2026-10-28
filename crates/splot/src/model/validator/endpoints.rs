//! Endpoints: which nodes the others can dial.

use crate::{
    config::Config,
    model::validator::types::{ValidationError, ValidationReport, ValidationWarning},
    types::config_location::{ConfigLocation, HubLoc, NodeLoc},
};

/// A node without an endpoint can't be dialled: it dials the others. So at least
/// one node needs an endpoint, a hub's node needs one (its clients dial it), and
/// two nodes without one have no tunnel between them.
pub(super) fn check_endpoints(config: &Config, report: &mut ValidationReport) {
    let undialable: Vec<_> = config
        .nodes
        .iter()
        .filter(|(_, node)| node.endpoint.is_none())
        .collect();

    for (name, node) in &undialable {
        if node.hub.is_some() {
            report.errors.push(ValidationError::HubOnUndialableNode {
                at: ConfigLocation::Node((*name).clone(), NodeLoc::Hub(HubLoc::Root)),
            });
        }
    }

    if config.nodes.len() > 1 && undialable.len() == config.nodes.len() {
        report.errors.push(ValidationError::NoDialableNode {
            at: ConfigLocation::Nodes,
        });
        return;
    }

    // Each pair once, at the node that sorts last.
    for (i, (name, _)) in undialable.iter().enumerate() {
        for (other, _) in &undialable[..i] {
            report.warnings.push(ValidationWarning::NoDirectTunnel {
                other: (*other).clone(),
                at: ConfigLocation::Node((*name).clone(), NodeLoc::Endpoint),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::{ValidationError, ValidationWarning},
        test_support::{error_at, has_error, has_warning, report, warning_at},
    };

    /// A node of the mesh; `endpoint` is its endpoint line, if any. Others dial
    /// a node with one, so it has a wanZone to let its listen port in.
    fn node(name: &str, key: char, ip: u8, endpoint: &str) -> String {
        let wan_zone = if endpoint.is_empty() {
            ""
        } else {
            "wanZone: wan"
        };
        format!(
            "
  {name}:
    platform:
      os: openwrt
    publicKey: {key}{rest}A=
    {endpoint}
    {wan_zone}
    listenPort: 51820
    meshIp: 10.100.0.{ip}",
            rest = key.to_string().repeat(41),
        )
    }

    fn mesh(nodes: &[String]) -> String {
        format!("meshNetwork: 10.100.0.0/16\nnodes:{}\n", nodes.concat())
    }

    #[test]
    fn a_node_may_have_no_endpoint() {
        let r = report(&mesh(&[
            node("Home", 'A', 1, "endpoint: 1.2.3.4"),
            node("Lake", 'B', 2, ""),
        ]));
        assert!(
            r.errors.is_empty(),
            "{:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
        assert!(
            r.warnings.is_empty(),
            "{:?}",
            r.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn some_node_must_have_an_endpoint() {
        let no_dialable_node =
            |e: &ValidationError| matches!(e, ValidationError::NoDialableNode { .. });

        let r = report(&mesh(&[node("Home", 'A', 1, ""), node("Lake", 'B', 2, "")]));
        assert!(error_at(&r, "nodes", no_dialable_node));
        // The error says it all: no warning for the pair on top.
        assert!(r.warnings.is_empty());

        // One node has no other to dial.
        let r = report(&mesh(&[node("Home", 'A', 1, "")]));
        assert!(!has_error(&r, no_dialable_node));

        let r = report(&mesh(&[
            node("Home", 'A', 1, ""),
            node("Lake", 'B', 2, "endpoint: lake.example.net"),
        ]));
        assert!(!has_error(&r, no_dialable_node));
    }

    #[test]
    fn a_hub_needs_an_endpoint() {
        let hub = "
    hub:
      network: 10.100.49.0/24";
        let hub_error =
            |e: &ValidationError| matches!(e, ValidationError::HubOnUndialableNode { .. });

        let r = report(&mesh(&[
            node("Home", 'A', 1, "endpoint: 1.2.3.4"),
            node("Lake", 'B', 2, "") + hub,
        ]));
        assert!(error_at(&r, "nodes.Lake.hub", hub_error));

        let r = report(&mesh(&[
            node("Home", 'A', 1, "endpoint: 1.2.3.4") + hub,
            node("Lake", 'B', 2, ""),
        ]));
        assert!(!has_error(&r, hub_error));
    }

    #[test]
    fn two_nodes_nobody_can_dial_have_no_tunnel() {
        let no_tunnel_with = |name: &'static str| move |w: &ValidationWarning| matches!(w, ValidationWarning::NoDirectTunnel { other, .. } if other.as_ref() == name);

        // Once per pair, at the node that sorts last; the dialable node is in none.
        let r = report(&mesh(&[
            node("Home", 'A', 1, "endpoint: 1.2.3.4"),
            node("Cabin", 'B', 2, ""),
            node("Lake", 'C', 3, ""),
            node("Pond", 'D', 4, ""),
        ]));
        assert!(warning_at(
            &r,
            "nodes.Lake.endpoint",
            no_tunnel_with("Cabin")
        ));
        assert!(warning_at(
            &r,
            "nodes.Pond.endpoint",
            no_tunnel_with("Cabin")
        ));
        assert!(warning_at(
            &r,
            "nodes.Pond.endpoint",
            no_tunnel_with("Lake")
        ));
        assert_eq!(r.warnings.len(), 3);
        assert!(!has_warning(&r, no_tunnel_with("Home")));
    }
}
