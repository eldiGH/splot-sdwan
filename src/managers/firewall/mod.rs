mod consts;
mod redirect;
mod rules;
mod types;
mod zones;

use log::{Level, debug, info, log_enabled};

use crate::{
    config::Config,
    managers::{
        NodeContext, UciManager, UciSection,
        firewall::{
            consts::FIREWALL_FILE_NAME,
            redirect::get_firewall_redirects,
            rules::{get_firewall_egress_rules, get_firewall_ingress_rules},
            zones::get_firewall_zones,
        },
    },
    model::Network,
    uci::UciBatchCommand,
};

pub struct FirewallManager;

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        FIREWALL_FILE_NAME
    }

    fn generate_commands(
        &self,
        config: &Config,
        network: &Network,
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand> {
        info!(
            "Generating firewall config for node '{}'",
            node_context.own_name
        );

        let zones = get_firewall_zones();
        let mut rules = get_firewall_ingress_rules(network, node_context.own_name);
        rules.extend(get_firewall_egress_rules(
            config,
            network,
            node_context.own_name,
        ));

        let redirects = get_firewall_redirects(config, node_context);

        info!(
            "  {} zone(s), {} rule(s), {} redirect(s)",
            zones.len(),
            rules.len(),
            redirects.len()
        );

        if log_enabled!(Level::Debug) {
            for zone in &zones {
                debug!(
                    "  Zone '{}': networks [{}]",
                    zone.name,
                    zone.network.join(", ")
                );
            }
            for rule in &rules {
                debug!(
                    "  Rule '{}' [{}]: {} src_ip(s) → {} dest_ip(s) on port {}",
                    rule.name,
                    rule.proto,
                    rule.src_ip.len(),
                    rule.dest_ip.len(),
                    rule.dest_port
                );
            }
            for redirect in &redirects {
                debug!(
                    "  Redirect '{}' [{}]: {}:{} → {}:{}",
                    redirect.name,
                    redirect.proto,
                    redirect.src,
                    redirect.src_dport,
                    redirect.dest_ip,
                    redirect.dest_port,
                )
            }
        }

        zones
            .iter()
            .flat_map(|zone| zone.to_uci_commands())
            .chain(rules.iter().flat_map(|rule| rule.to_uci_commands()))
            .chain(
                redirects
                    .iter()
                    .flat_map(|redirect| redirect.to_uci_commands()),
            )
            .collect()
    }
}
