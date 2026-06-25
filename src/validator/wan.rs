use std::collections::{HashMap, HashSet};

use crate::{
    config::{Client, Config, Node, ServiceHost, ServiceWan, WanResolveError},
    consts,
    types::{
        config_location::{ConfigLocation, NodeLoc, ServiceLoc, VpnLoc, WanLoc, ZoneLoc},
        identifier::Identifier,
        wan_via_target::WanViaTarget,
    },
    validator::types::{ValidationError, ValidationReport, ValidationWarning},
};

fn validate_service_wan<'a>(
    service_wan: &'a Option<ServiceWan>,
    nodes: &HashMap<Identifier, Node>,
    client: Option<&Client>,
    wan_nodes_used: &mut HashSet<&'a Identifier>,
    report: &mut ValidationReport,
    locate: impl Fn(ServiceLoc) -> ConfigLocation,
) {
    let Some(wan) = service_wan else { return };
    let locate = || locate(ServiceLoc::Wan(WanLoc::Via));

    for via in &wan.via {
        let node_name = via.node();

        let Some(node) = nodes.get(node_name) else {
            report.errors.push(ValidationError::InvalidWanVia {
                node_name: node_name.clone(),
                at: locate(),
            });
            continue;
        };

        if node.wan_zone.is_none() {
            report.errors.push(ValidationError::WanViaNodeNoWanZone {
                node_name: node_name.clone(),
                at: locate(),
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
                            at: locate(),
                        }
                    }

                    WanResolveError::QualifiedNetworkMissing { network } => {
                        ValidationError::WanViaNetworkMissing {
                            node: node_name.clone(),
                            network,
                            at: locate(),
                        }
                    }

                    WanResolveError::Unreachable => ValidationError::WanViaUnreachable {
                        node: node_name.clone(),
                        at: locate(),
                    },

                    WanResolveError::QualifiedClientNotOnNetwork { network } => {
                        ValidationError::WanViaClientNotOnNetwork {
                            node: node_name.clone(),
                            network,
                            at: locate(),
                        }
                    }
                };

                report.errors.push(report_err);
            }
        } else if matches!(via, WanViaTarget::Qualified(_)) {
            report
                .errors
                .push(ValidationError::WanViaQualifiedOnNonClient { at: locate() });
        }
    }
}

fn check_services_wan(config: &Config, report: &mut ValidationReport) {
    let mut wan_nodes_used = HashSet::new();

    for (service, host) in config.services() {
        let client = match host {
            ServiceHost::Client { client_name, .. } => config.clients.get(client_name),
            _ => None,
        };

        validate_service_wan(
            &service.wan,
            &config.nodes,
            client,
            &mut wan_nodes_used,
            report,
            |service_loc| host.to_location(service_loc),
        );
    }

    for (node_name, node) in &config.nodes {
        if node.wan_zone.is_some() && !wan_nodes_used.contains(node_name) {
            report.warnings.push(ValidationWarning::UnusedWanZone {
                at: ConfigLocation::Node(node_name.clone(), NodeLoc::WanZone),
            })
        }
    }
}

fn check_wan_zone(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        let Some(wan_zone) = &node.wan_zone else {
            continue;
        };

        let at = || ConfigLocation::Node(node_name.clone(), NodeLoc::WanZone);

        if wan_zone == consts::MESH_INTERFACE_NAME {
            report.errors.push(ValidationError::WanZoneReservedName {
                wan_zone: wan_zone.clone(),
                at: at(),
            });
            continue;
        }

        if node.zones.contains_key(wan_zone) {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(wan_zone.clone(), ZoneLoc::Root),
                ),
                at: at(),
            });
        }

        if node.vpn_interfaces.contains_key(wan_zone) {
            report.errors.push(ValidationError::WanZoneNameCollision {
                wan_zone: wan_zone.clone(),
                with: ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::VpnInterface(wan_zone.clone(), VpnLoc::Root),
                ),
                at: at(),
            });
        }
    }
}

pub(super) fn check_wan(config: &Config, report: &mut ValidationReport) {
    check_services_wan(config, report);
    check_wan_zone(config, report);
}
