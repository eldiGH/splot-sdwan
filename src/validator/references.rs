use std::collections::HashSet;

use crate::{
    config::{Config, Service},
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc,
            NodeLoc::{self, VpnInterface, Zone},
            ServiceLoc,
            VpnClientLoc::{self},
            VpnLoc::Client,
            ZoneLoc,
        },
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
    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            check_service(service, known_references, report, |service_loc| {
                ConfigLocation::Client(
                    client_name.clone(),
                    ClientLoc::Service(service_name.clone(), service_loc),
                )
            });
        }
    }

    for (node_name, node) in &config.nodes {
        for (service_name, service) in &node.services {
            check_service(service, known_references, report, |service_loc| {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Service(service_name.clone(), service_loc),
                )
            });
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    check_service(service, known_references, report, |service_loc| {
                        ConfigLocation::Node(
                            node_name.clone(),
                            Zone(
                                zone_name.clone(),
                                ZoneLoc::Device(
                                    device_name.clone(),
                                    DeviceLoc::Service(service_name.clone(), service_loc),
                                ),
                            ),
                        )
                    });
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    check_service(service, known_references, report, |service_loc| {
                        ConfigLocation::Node(
                            node_name.clone(),
                            VpnInterface(
                                vpn_interface_name.clone(),
                                Client(
                                    vpn_interface_client_name.clone(),
                                    VpnClientLoc::Service(service_name.clone(), service_loc),
                                ),
                            ),
                        )
                    });
                }
            }
        }
    }
}
