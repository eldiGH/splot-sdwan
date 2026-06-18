use std::collections::{HashMap, HashSet};

use crate::{
    config::{Client, Config, Node, ServiceWan, WanResolveError},
    consts,
    types::{identifier::Identifier, wan_via_target::WanViaTarget},
    validator::types::{ConfigPath, ValidationError, ValidationReport, ValidationWarning},
};

fn validate_service_wan<'a>(
    service_wan: &'a Option<ServiceWan>,
    nodes: &HashMap<Identifier, Node>,
    client: Option<&Client>,
    wan_nodes_used: &mut HashSet<&'a Identifier>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    let Some(wan) = service_wan else { return };
    let make_path = || make_path().extend(["wan", "via"]);

    for via in &wan.via {
        let node_name = via.node();

        let Some(node) = nodes.get(node_name) else {
            report.errors.push(ValidationError::InvalidWanVia {
                node_name: node_name.clone(),
                at: make_path(),
            });
            continue;
        };

        if node.wan_zone.is_none() {
            report.errors.push(ValidationError::WanViaNodeNoWanZone {
                node_name: node_name.clone(),
                at: make_path(),
            });
        }

        wan_nodes_used.insert(node_name);

        if let Some(client) = client {
            if let Err(err) = client.resolve_wan_target(via, node) {
                let report_err = match err {
                    WanResolveError::AmbiguousVpn { candidates } => {
                        ValidationError::WanViaAmbiguous {
                            node: node_name.clone(),
                            candidates,
                            at: make_path(),
                        }
                    }

                    WanResolveError::QualifiedNetworkMissing { network } => {
                        ValidationError::WanViaNetworkMissing {
                            node: node_name.clone(),
                            network,
                            at: make_path(),
                        }
                    }

                    WanResolveError::Unreachable => ValidationError::WanViaUnreachable {
                        node: node_name.clone(),
                        at: make_path(),
                    },

                    WanResolveError::QualifiedClientNotOnNetwork { network } => {
                        ValidationError::WanViaClientNotOnNetwork {
                            node: node_name.clone(),
                            network,
                            at: make_path(),
                        }
                    }
                };

                report.errors.push(report_err);
            }
        } else if matches!(via, WanViaTarget::Qualified(_)) {
            report
                .errors
                .push(ValidationError::WanViaQualifiedOnNonClient { at: make_path() });
        }
    }
}

fn check_services_wan(config: &Config, report: &mut ValidationReport) {
    let mut wan_nodes_used = HashSet::new();

    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            validate_service_wan(
                &service.wan,
                &config.nodes,
                Some(client),
                &mut wan_nodes_used,
                report,
                || {
                    ConfigPath::new([
                        "clients",
                        client_name.as_ref(),
                        "services",
                        service_name.as_ref(),
                    ])
                },
            );
        }
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

        for (service_name, service) in &node.services {
            validate_service_wan(
                &service.wan,
                &config.nodes,
                None,
                &mut wan_nodes_used,
                report,
                || make_path().extend(["services", service_name.as_ref()]),
            );
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    validate_service_wan(
                        &service.wan,
                        &config.nodes,
                        None,
                        &mut wan_nodes_used,
                        report,
                        || {
                            make_path().extend([
                                "zones",
                                zone_name.as_ref(),
                                "devices",
                                device_name.as_ref(),
                                "services",
                                service_name.as_ref(),
                            ])
                        },
                    )
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    validate_service_wan(
                        &service.wan,
                        &config.nodes,
                        None,
                        &mut wan_nodes_used,
                        report,
                        || {
                            make_path().extend([
                                "vpnInterfaces",
                                vpn_interface_name.as_ref(),
                                "clients",
                                vpn_interface_client_name.as_ref(),
                                "services",
                                service_name.as_ref(),
                            ])
                        },
                    );
                }
            }
        }
    }

    for (node_name, node) in &config.nodes {
        if node.wan_zone.is_some() && !wan_nodes_used.contains(node_name) {
            report.warnings.push(ValidationWarning::UnusedWanZone {
                at: ConfigPath::new(["nodes", node_name.as_ref(), "wanZone"]),
            })
        }
    }
}

fn check_wan_zone(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        let Some(wan_zone) = &node.wan_zone else {
            continue;
        };

        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);
        let at = || make_path().extend(["wanZone"]);

        if wan_zone == consts::MESH_INTERFACE_NAME {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: ConfigPath::new(["<splot mesh interface>"]),
                at: at(),
            });
            continue;
        }

        if node.zones.contains_key(wan_zone) {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: make_path().extend(["zones", wan_zone.as_ref()]),
                at: at(),
            });
        }

        if node.vpn_interfaces.contains_key(wan_zone) {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: make_path().extend(["vpnInterfaces", wan_zone.as_ref()]),
                at: at(),
            });
        }
    }
}

pub(super) fn check_wan(config: &Config, report: &mut ValidationReport) {
    check_services_wan(config, report);
    check_wan_zone(config, report);
}
