mod consts;
mod redirect;
mod rules;
mod tag_resolution;
mod types;
mod zones;

use log::{Level, debug, info, log_enabled};

use crate::{
    config::Config,
    managers::{
        UciManager,
        firewall::{
            consts::FIREWALL_FILE_NAME,
            redirect::get_firewall_redirects,
            rules::{get_firewall_egress_rules, get_firewall_ingress_rules},
            tag_resolution::build_tags_resolution_map,
            zones::get_firewall_zones,
        },
    },
    types::identifier::Identifier,
    uci::UciBatchCommand,
};

pub struct FirewallManager;

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        FIREWALL_FILE_NAME
    }

    fn generate_commands(&self, config: &Config, own_name: &Identifier) -> Vec<UciBatchCommand> {
        info!("Generating firewall config for node '{own_name}'");

        let tags = build_tags_resolution_map(config, own_name);
        debug!("  Resolved {} tag(s)", tags.len());

        let zones = get_firewall_zones(config, own_name);
        let mut rules = get_firewall_ingress_rules(config, own_name, &tags);
        rules.extend(get_firewall_egress_rules(config, own_name, &tags));

        let redirects = get_firewall_redirects(config, own_name);

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
