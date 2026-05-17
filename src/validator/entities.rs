use crate::{
    config::{Client, Config, ZoneOrVpnInterface},
    validator::types::{ConfigPath, ValidationError, ValidationReport, ValidationWarning},
};

fn client_has_ips_of_type(
    client: &Client,
    config: &Config,
    predicate: impl Fn(&ZoneOrVpnInterface) -> bool,
) -> bool {
    client.ips.iter().any(|(node_name, node_networks)| {
        node_networks.keys().any(|network_name| {
            config
                .nodes
                .get(node_name)
                .and_then(|node| node.network_by_name(network_name))
                .is_some_and(|network| predicate(&network))
        })
    })
}

fn check_clients_macs(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        let is_in_any_zone_network = client_has_ips_of_type(client, config, |network| {
            matches!(network, ZoneOrVpnInterface::Zone(_))
        });

        let make_path = || ConfigPath::new(["clients", client_name, "macs"]);

        match (is_in_any_zone_network, client.macs.is_empty()) {
            (true, true) => report
                .errors
                .push(ValidationError::MacMissing { at: make_path() }),
            (false, false) => report
                .warnings
                .push(ValidationWarning::UnusedMac { at: make_path() }),
            _ => {}
        };
    }
}

fn check_clients_public_key(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        let is_in_any_vpn_interface_network = client_has_ips_of_type(client, config, |network| {
            matches!(network, ZoneOrVpnInterface::VpnInterface(_))
        });
        let mesh_ip_present = client.mesh_ip.is_some();

        let make_path = || ConfigPath::new(["clients", client_name, "publicKey"]);

        match (
            is_in_any_vpn_interface_network,
            client.public_key.is_some(),
            mesh_ip_present,
        ) {
            (true, false, _) | (_, false, true) => {
                report.errors.push(ValidationError::PublicKeyMissing {
                    required_for_mesh: mesh_ip_present,
                    required_for_vpn_interface: is_in_any_vpn_interface_network,
                    at: make_path(),
                })
            }
            (false, true, false) => report
                .warnings
                .push(ValidationWarning::UnusedPublicKey { at: make_path() }),
            _ => {}
        }
    }
}

fn check_client_networks(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        for (node_name, networks) in &client.ips {
            let make_path = || ConfigPath::new(["clients", client_name, "ips", node_name]);

            let Some(node) = config.nodes.get(node_name) else {
                report.errors.push(ValidationError::NodeMissing {
                    node_name: node_name.clone(),
                    at: make_path(),
                });
                continue;
            };

            for network_name in networks.keys() {
                let make_path = || make_path().extend([network_name]);

                let Some(network) = node.network_by_name(network_name) else {
                    report.errors.push(ValidationError::NodeNetworkMissing {
                        node_name: node_name.clone(),
                        network_name: network_name.clone(),
                        at: make_path(),
                    });
                    continue;
                };

                if let ZoneOrVpnInterface::Zone(zone) = network
                    && zone.address.is_none()
                {
                    report
                        .errors
                        .push(ValidationError::ClientIpInAddresslessZone {
                            client_name: client_name.clone(),
                            zone_name: network_name.clone(),
                            at: make_path(),
                        })
                }
            }
        }
    }
}

fn check_zones(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        for (zone_name, zone) in &node.zones {
            let make_path = || ConfigPath::new(["nodes", node_name, "zones", zone_name]);

            if zone.address.is_none() && !zone.devices.is_empty() {
                report
                    .errors
                    .push(ValidationError::DevicesInAddresslessZone {
                        node_name: node_name.clone(),
                        zone_name: zone_name.clone(),
                        at: make_path().extend(["devices"]),
                    })
            }
        }
    }
}

fn check_unreachable_clients(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        if client.ips.is_empty() && client.mesh_ip.is_none() {
            report.warnings.push(ValidationWarning::UnreachableClient {
                at: ConfigPath::new(["clients", client_name]),
            });
        }
    }
}

pub(super) fn check_entities(config: &Config, report: &mut ValidationReport) {
    check_client_networks(config, report);
    check_clients_macs(config, report);
    check_clients_public_key(config, report);
    check_zones(config, report);
    check_unreachable_clients(config, report);
}
