use std::collections::{HashMap, hash_map::Entry};

use crate::{
    config::{Client, Config},
    types::{
        config_location::{ClientIpLoc, ClientLoc, ConfigLocation, NodeLoc},
        wg_key::WgPublicKey,
    },
    validator::types::{ValidationError, ValidationReport, ValidationWarning},
};

fn client_is_in_any_zone(client: &Client, config: &Config) -> bool {
    client.ips.iter().any(|(node_name, client_zones)| {
        config.nodes.get(node_name).is_some_and(|node| {
            client_zones
                .keys()
                .any(|zone| node.zones.contains_key(zone))
        })
    })
}

fn check_clients_macs(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        match (
            client_is_in_any_zone(client, config),
            client.macs.is_empty(),
        ) {
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

/// A client is a WireGuard peer exactly when it has a mesh IP.
fn check_clients_public_key(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        let at = || ConfigLocation::Client(client_name.clone(), ClientLoc::PublicKey);

        match (client.mesh_ip.is_some(), client.public_key.is_some()) {
            (true, false) => report
                .errors
                .push(ValidationError::PublicKeyMissing { at: at() }),
            (false, true) => report
                .warnings
                .push(ValidationWarning::UnusedPublicKey { at: at() }),
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
                if !node.zones.contains_key(network_name) {
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

fn note_public_key<'a>(
    key: &'a WgPublicKey,
    at: ConfigLocation,
    seen: &mut HashMap<&'a WgPublicKey, ConfigLocation>,
    report: &mut ValidationReport,
) {
    match seen.entry(key) {
        Entry::Occupied(first) => report.errors.push(ValidationError::DuplicatePublicKey {
            at,
            with: first.get().clone(),
        }),
        Entry::Vacant(slot) => {
            slot.insert(at);
        }
    }
}

/// Every node and global client needs its own public key. Two nodes
/// sharing one make "which node am I" ambiguous, and WireGuard can't hold two
/// peers with the same key on one interface.
fn check_public_key_uniqueness(config: &Config, report: &mut ValidationReport) {
    let mut seen = HashMap::new();

    for (node_name, node) in &config.nodes {
        note_public_key(
            &node.public_key,
            ConfigLocation::Node(node_name.clone(), NodeLoc::PublicKey),
            &mut seen,
            report,
        );
    }

    for (client_name, client) in &config.clients {
        if let Some(public_key) = &client.public_key {
            note_public_key(
                public_key,
                ConfigLocation::Client(client_name.clone(), ClientLoc::PublicKey),
                &mut seen,
                report,
            );
        }
    }
}

pub(super) fn check_entities(config: &Config, report: &mut ValidationReport) {
    check_client_networks(config, report);
    check_clients_macs(config, report);
    check_clients_public_key(config, report);
    check_public_key_uniqueness(config, report);
    check_unreachable_clients(config, report);
}
