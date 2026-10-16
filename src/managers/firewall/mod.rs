mod consts;
mod redirect;
mod rules;
mod zones;

use log::{Level, debug, info, log_enabled};

use crate::{
    managers::{
        UciManager, UciSection,
        firewall::{consts::FIREWALL_FILE_NAME, zones::MeshZone},
    },
    plan::{NodePlan, firewall::Verdict},
    splot_config::SplotConfig,
    uci::UciBatchCommand,
};

/// A verdict as fw4 spells it.
fn target(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Drop => "DROP",
    }
}

pub struct FirewallManager;

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        FIREWALL_FILE_NAME
    }

    fn generate_commands(
        &self,
        plan: &NodePlan,
        _splot_config: &SplotConfig,
    ) -> Vec<UciBatchCommand> {
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
}
