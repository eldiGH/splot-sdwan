mod entities;
mod identifiers;
mod names;
mod networks;
mod ports;
mod tags;
mod types;
mod utils;

use std::collections::HashSet;

use crate::{
    config::Config,
    validator::{
        entities::check_entities, identifiers::check_identifiers_resolution, names::validate_names,
        networks::check_networks, ports::check_ports, tags::validate_tags, types::ValidationReport,
    },
};

pub fn validate_config(config: &Config) -> ValidationReport {
    let mut report = ValidationReport::default();

    let names = validate_names(config, &mut report);
    let tags = validate_tags(config, &mut report, &names);
    let identifiers: HashSet<String> = names.into_iter().chain(tags).collect();
    check_identifiers_resolution(config, &identifiers, &mut report);

    check_entities(config, &mut report);

    check_networks(config, &mut report);

    check_ports(config, &mut report);

    report
}
