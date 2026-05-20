use std::collections::HashSet;

use crate::{
    config::{Config, Service},
    types::allow_from_ref::AllowFromRef,
    validator::types::{ConfigPath, ValidationError, ValidationReport, ValidationWarning},
};

fn check_service(
    service: &Service,
    known_references: &HashSet<AllowFromRef>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    let has_lan_access = !service.allow_from.is_empty();
    let has_wan_access = service.wan.as_ref().is_some_and(|wan| !wan.via.is_empty());

    if !has_lan_access && !has_wan_access {
        report
            .warnings
            .push(ValidationWarning::UnreachableService { at: make_path() });
    }

    for reference in &service.allow_from {
        if !known_references.contains(reference) {
            report.errors.push(ValidationError::UnknownRef {
                reference: reference.clone(),
                at: make_path().extend(["allowFrom"]),
            })
        }
    }
}

pub(super) fn check_references_resolution(
    config: &Config,
    known_references: &HashSet<AllowFromRef>,
    report: &mut ValidationReport,
) {
    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            check_service(service, known_references, report, || {
                ConfigPath::new([
                    "clients",
                    client_name.as_ref(),
                    "services",
                    service_name.as_ref(),
                ])
            });
        }
    }

    for (node_name, node) in &config.nodes {
        for (service_name, service) in &node.services {
            check_service(service, known_references, report, || {
                ConfigPath::new([
                    "nodes",
                    node_name.as_ref(),
                    "services",
                    service_name.as_ref(),
                ])
            });
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    check_service(service, known_references, report, || {
                        ConfigPath::new([
                            "nodes",
                            node_name.as_ref(),
                            "zones",
                            zone_name.as_ref(),
                            "devices",
                            device_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                        ])
                    });
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    check_service(service, known_references, report, || {
                        ConfigPath::new([
                            "nodes",
                            node_name.as_ref(),
                            "vpnInterfaces",
                            vpn_interface_name.as_ref(),
                            "clients",
                            vpn_interface_client_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                        ])
                    });
                }
            }
        }
    }
}
