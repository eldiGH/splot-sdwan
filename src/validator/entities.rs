use crate::{
    config::{Client, Config, ZoneOrVpnInterface},
    types::config_location::{ClientIpLoc, ClientLoc, ConfigLocation},
    validator::types::{ValidationError, ValidationReport, ValidationWarning},
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

        match (is_in_any_zone_network, client.macs.is_empty()) {
            (true, true) => report.errors.push(ValidationError::MacMissing {
                at: ConfigLocation::Client(client_name.clone(), ClientLoc::Macs),
            }),
            (false, false) => report.warnings.push(ValidationWarning::UnusedMac {
                at: ConfigLocation::Client(client_name.clone(), ClientLoc::Macs),
            }),
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

        match (
            is_in_any_vpn_interface_network,
            client.public_key.is_some(),
            mesh_ip_present,
        ) {
            (true, false, _) | (_, false, true) => {
                report.errors.push(ValidationError::PublicKeyMissing {
                    required_for_mesh: mesh_ip_present,
                    required_for_vpn_interface: is_in_any_vpn_interface_network,
                    at: ConfigLocation::Client(client_name.clone(), ClientLoc::PublicKey),
                })
            }
            (false, true, false) => report.warnings.push(ValidationWarning::UnusedPublicKey {
                at: ConfigLocation::Client(client_name.clone(), ClientLoc::PublicKey),
            }),
            _ => {}
        }
    }
}

fn check_client_networks(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        for (node_name, networks) in &client.ips {
            let Some(node) = config.nodes.get(node_name) else {
                report.errors.push(ValidationError::NodeMissing {
                    node_name: node_name.clone(),
                    at: ConfigLocation::Client(
                        client_name.clone(),
                        ClientLoc::Ip(node_name.clone(), ClientIpLoc::Root),
                    ),
                });
                continue;
            };

            for network_name in networks.keys() {
                if node.network_by_name(network_name).is_none() {
                    report.errors.push(ValidationError::NodeNetworkMissing {
                        node_name: node_name.clone(),
                        network_name: network_name.clone(),
                        at: ConfigLocation::Client(
                            client_name.clone(),
                            ClientLoc::Ip(
                                node_name.clone(),
                                ClientIpLoc::Network(network_name.clone()),
                            ),
                        ),
                    });
                }
            }
        }
    }
}

fn check_unreachable_clients(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        if client.ips.is_empty() && client.mesh_ip.is_none() {
            report.warnings.push(ValidationWarning::UnreachableClient {
                at: ConfigLocation::Client(client_name.clone(), ClientLoc::Root),
            });
        }
    }
}

pub(super) fn check_entities(config: &Config, report: &mut ValidationReport) {
    check_client_networks(config, report);
    check_clients_macs(config, report);
    check_clients_public_key(config, report);
    check_unreachable_clients(config, report);
}
