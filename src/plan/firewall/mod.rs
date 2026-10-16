//! The node's firewall: the mesh zone splot owns, the flows it lets through, and
//! the port forwards from the internet.

pub mod redirect;
pub mod rules;

use std::fmt;

use crate::model::{Network, node::Node};
use redirect::Redirect;
use rules::Rule;

#[derive(Debug)]
pub struct FirewallPlan {
    /// The mesh zone: everything that arrives over WireGuard.
    pub mesh_zone: ZonePolicy,
    /// Ingress rules first, then egress.
    pub rules: Vec<Rule>,
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

    FirewallPlan {
        // Access is granted only by rules.
        mesh_zone: ZonePolicy {
            input: Verdict::Drop,
            output: Verdict::Accept,
            forward: Verdict::Drop,
        },
        rules,
        redirects: redirect::redirects(network, own),
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
        let ZonePolicy {
            input,
            output,
            forward,
        } = self.mesh_zone;
        writeln!(
            f,
            "mesh zone: input {input}, output {output}, forward {forward}"
        )?;

        for rule in &self.rules {
            writeln!(f, "{rule}")?;
        }
        for redirect in &self.redirects {
            writeln!(f, "{redirect}")?;
        }

        Ok(())
    }
}
