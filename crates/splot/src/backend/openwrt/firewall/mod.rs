mod ping;
mod redirect;
mod rules;
mod zones;

use log::{Level, debug, info, log_enabled};

use super::section::{Section, UciSection};
use crate::{
    model::host::HostRef,
    plan::firewall::{FirewallPlan, Verdict},
};
use zones::MeshZone;

pub(super) const FILE: &str = "firewall";

/// A host's part of a section id, with its node's name when it's inside a node,
/// so it can't clash with another node's host of the same name.
fn qualified_host_id(host: &HostRef) -> Vec<&str> {
    match host {
        HostRef::Local { node, name } => vec![node.as_ref(), name.as_ref()],
        _ => vec![host.name().as_ref()],
    }
}

/// A verdict as fw4 spells it.
fn target(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Drop => "DROP",
    }
}

/// The plan's firewall section as the `firewall` file's sections: the mesh zone
/// and the peers' ping (if any), then the rules, then the redirects.
pub(super) fn render(firewall: &FirewallPlan) -> Vec<Section> {
    info!("Generating firewall config");
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

    let zone = firewall
        .mesh_zone
        .as_ref()
        .map(|policy| MeshZone(policy).to_section());
    let ping = firewall.ping.as_ref().map(|ping| ping.to_section());
    let rules = firewall.rules.iter().map(|rule| rule.to_section());
    let redirects = firewall
        .redirects
        .iter()
        .map(|redirect| redirect.to_section());

    zone.into_iter()
        .chain(ping)
        .chain(rules)
        .chain(redirects)
        .collect()
}
