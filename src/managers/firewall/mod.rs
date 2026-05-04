mod consts;
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
            consts::FIREWALL_FILE_NAME, rules::get_firewall_ingress_rules,
            tag_resolution::build_tags_resolution_map, zones::get_firewall_zones,
        },
    },
    uci::UciBatchCommand,
};

pub struct FirewallManager;

impl UciManager for FirewallManager {
    fn config_file(&self) -> &'static str {
        FIREWALL_FILE_NAME
    }

    fn generate_commands(&self, config: &Config, own_name: &str) -> Vec<UciBatchCommand> {
        info!("Generating firewall config for node '{own_name}'");

        let tags = build_tags_resolution_map(config, own_name);
        debug!("  Resolved {} tag(s)", tags.len());

        let zones = get_firewall_zones(config, own_name);
        let rules = get_firewall_ingress_rules(config, own_name, &tags);

        info!("  {} zone(s), {} rule(s)", zones.len(), rules.len());

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
                    "  Rule '{}': {} src_ip(s) → {} dest_ip(s) on port {}",
                    rule.name,
                    rule.src_ip.len(),
                    rule.dest_ip.len(),
                    rule.dest_port
                );
            }
        }

        zones
            .iter()
            .flat_map(|zone| zone.to_uci_commands())
            .chain(rules.iter().flat_map(|rule| rule.to_uci_commands()))
            .collect()
    }
}
