mod redirect;
mod rules;
mod zones;

use std::iter;

use log::{Level, debug, info, log_enabled};

use super::section::{Section, UciSection};
use crate::plan::{NodePlan, firewall::Verdict};
use zones::MeshZone;

pub(super) const FILE: &str = "firewall";

/// A verdict as fw4 spells it.
fn target(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Drop => "DROP",
    }
}

/// The plan's firewall section as the `firewall` file's sections: the mesh zone,
/// then the rules, then the redirects.
pub(super) fn render(plan: &NodePlan) -> Vec<Section> {
    let firewall = &plan.firewall;

    info!("Generating firewall config for node '{}'", plan.node);
    info!(
        "  {} rule(s), {} redirect(s)",
        firewall.rules.len(),
        firewall.redirects.len()
    );

    if log_enabled!(Level::Debug) {
        for rule in &firewall.rules {
            debug!("  {rule}");
        }
        for redirect in &firewall.redirects {
            debug!("  {redirect}");
        }
    }

    let zone = MeshZone(&firewall.mesh_zone).to_section();
    let rules = firewall.rules.iter().map(|rule| rule.to_section());
    let redirects = firewall
        .redirects
        .iter()
        .map(|redirect| redirect.to_section());

    iter::once(zone).chain(rules).chain(redirects).collect()
}
