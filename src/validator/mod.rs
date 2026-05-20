mod entities;
mod names;
mod networks;
mod ports;
mod references;
mod tags;
mod types;
mod wan;

use std::collections::HashSet;

use crate::{
    config::Config,
    types::allow_from_ref::AllowFromRef,
    validator::{
        entities::check_entities, names::validate_names, networks::check_networks,
        ports::check_ports, references::check_references_resolution, tags::validate_tags,
        types::ValidationReport, wan::check_wan,
    },
};

pub fn validate_config(config: &Config) -> ValidationReport {
    let mut report = ValidationReport::default();

    let names = validate_names(config, &mut report);
    let tags = validate_tags(config, &mut report, &names);
    let refs: HashSet<AllowFromRef> = names.into_iter().chain(tags).collect();
    check_references_resolution(config, &refs, &mut report);

    check_entities(config, &mut report);

    check_networks(config, &mut report);

    check_ports(config, &mut report);

    check_wan(config, &mut report);

    report
}
