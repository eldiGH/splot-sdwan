use std::collections::HashSet;

use crate::{
    config::{Config, Service},
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{ConfigLocation, ServiceLoc},
    },
    validator::types::{ValidationError, ValidationReport, ValidationWarning},
};

fn check_service(
    service: &Service,
    known_references: &HashSet<AllowFromRef>,
    report: &mut ValidationReport,
    locate: impl Fn(ServiceLoc) -> ConfigLocation,
) {
    let has_lan_access = !service.allow_from.is_empty();
    let has_wan_access = service.wan.as_ref().is_some_and(|wan| !wan.via.is_empty());

    if !has_lan_access && !has_wan_access {
        report.warnings.push(ValidationWarning::UnreachableService {
            at: locate(ServiceLoc::Root),
        });
    }

    for reference in &service.allow_from {
        if !known_references.contains(reference) {
            report.errors.push(ValidationError::UnknownRef {
                reference: reference.clone(),
                at: locate(ServiceLoc::AllowFrom),
            })
        }
    }
}

pub(super) fn check_references_resolution(
    config: &Config,
    known_references: &HashSet<AllowFromRef>,
    report: &mut ValidationReport,
) {
    for (service, host) in config.services() {
        check_service(service, known_references, report, |service_loc| {
            host.to_location(service_loc)
        });
    }
}
