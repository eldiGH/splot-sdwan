mod redirect;
mod rules;
mod zones;

use log::{Level, debug, info, log_enabled};

use super::{section::UciSection, uci::UciBatchCommand};
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

/// The plan's firewall section as the `firewall` file's commands: the mesh zone,
/// then the rules, then the redirects.
pub(super) fn render(plan: &NodePlan) -> Vec<UciBatchCommand> {
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

    MeshZone(&firewall.mesh_zone)
        .to_uci_commands()
        .into_iter()
        .chain(
            firewall
                .rules
                .iter()
                .flat_map(|rule| rule.to_uci_commands()),
        )
        .chain(
            firewall
                .redirects
                .iter()
                .flat_map(|redirect| redirect.to_uci_commands()),
        )
        .collect()
}
