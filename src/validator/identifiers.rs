use std::collections::HashSet;

use crate::{
    config::{Config, Service},
    validator::types::{ConfigPath, ValidationError, ValidationReport, ValidationWarning},
};

fn check_service(
    service: &Service,
    identifiers: &HashSet<String>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    if service.allow_from.is_empty() {
        report
            .warnings
            .push(ValidationWarning::ServiceAllowFromEmpty { at: make_path() });
        return;
    }

    for identifier in &service.allow_from {
        if !identifiers.contains(identifier) {
            report.errors.push(ValidationError::UnknownIdentifier {
                identifier: identifier.clone(),
                at: make_path(),
            })
        }
    }
}

pub(super) fn check_identifiers_resolution(
    config: &Config,
    identifiers: &HashSet<String>,
    report: &mut ValidationReport,
) {
    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            check_service(service, identifiers, report, || {
                ConfigPath::new([
                    "clients",
                    client_name,
                    "services",
                    service_name,
                    "allowFrom",
                ])
            });
        }
    }

    for (node_name, node) in &config.nodes {
        for (service_name, service) in &node.services {
            check_service(service, identifiers, report, || {
                ConfigPath::new(["nodes", node_name, "services", service_name, "allowFrom"])
            });
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    check_service(service, identifiers, report, || {
                        ConfigPath::new([
                            "nodes",
                            node_name,
                            "zones",
                            zone_name,
                            "devices",
                            device_name,
                            "services",
                            service_name,
                            "allowFrom",
                        ])
                    });
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    check_service(service, identifiers, report, || {
                        ConfigPath::new([
                            "nodes",
                            node_name,
                            "vpnInterfaces",
                            vpn_interface_name,
                            "clients",
                            vpn_interface_client_name,
                            "services",
                            service_name,
                            "allowFrom",
                        ])
                    });
                }
            }
        }
    }
}
