use std::collections::{HashMap, hash_map::Entry};

use crate::{
    config::{Client, Config},
    model::validator::types::{ValidationError, ValidationReport, ValidationWarning},
    types::{
        config_location::{ClientIpLoc, ClientLoc, ConfigLocation, HubClientLoc, HubLoc, NodeLoc},
        wg_key::WgPublicKey,
    },
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

/// Every node, hub client and global client needs its own public key. Two nodes
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

    for (node_name, node) in &config.nodes {
        let Some(hub) = &node.hub else { continue };

        for (client_name, client) in &hub.clients {
            note_public_key(
                &client.public_key,
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Hub(HubLoc::Client(client_name.clone(), HubClientLoc::PublicKey)),
                ),
                &mut seen,
                report,
            );
        }
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

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::{
            HUB_HOME,
            types::{ValidationError, ValidationWarning},
        },
        test_support::{error_at, has_error, has_warning, report},
    };

    #[test]
    fn entities_mac_missing() {
        // Client with a zone IP but no macs.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
clients:
  Phone:
    ips:
      Home:
        lan: 192.168.1.50
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::MacMissing { .. }
        )));
    }

    #[test]
    fn entities_unused_mac_warning() {
        // Client with macs but no zone IPs.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedMac { .. }
        )));
    }

    #[test]
    fn entities_public_key_missing_for_mesh() {
        // Client with meshIp but no publicKey.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PublicKeyMissing { .. }
        )));
    }

    #[test]
    fn entities_unused_public_key_warning() {
        // Client with publicKey but no meshIp.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Orphan:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedPublicKey { .. }
        )));
    }

    #[test]
    fn entities_unreachable_client_warning() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Ghost: {}
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnreachableClient { .. }
        )));
    }

    #[test]
    fn entities_node_missing() {
        // client.ips references a node that does not exist in nodes.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    ips:
      NoSuchNode:
        lan: 192.168.1.50
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::NodeMissing { node_name, .. } if node_name == "NoSuchNode")
        ));
    }

    #[test]
    fn entities_node_network_missing() {
        // client.ips.Home references "guest" but Home has no "guest" network.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
clients:
  Phone:
    ips:
      Home:
        guest: 192.168.99.50
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::NodeNetworkMissing { network_name, .. } if network_name == "guest")
        ));
    }

    // Every node and global client needs its own public key: two nodes
    // sharing one make "which node am I" ambiguous, and WireGuard can't have two
    // peers with the same key on one interface. The later occurrence is flagged.
    #[test]
    fn entities_duplicate_public_key_between_nodes() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        // Cabin sorts first, so Home's key is the duplicate.
        assert!(error_at(&r, "nodes.Home.publicKey", |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Cabin.publicKey"
        )));
    }

    #[test]
    fn entities_duplicate_public_key_node_and_global_client() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    meshIp: 10.100.0.100
",
        );
        assert!(error_at(&r, "clients.Phone.publicKey", |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { with, .. }
                if with.to_string() == "nodes.Home.publicKey"
        )));
    }

    #[test]
    fn entities_distinct_public_keys_are_fine() {
        // Same shape as above, every key distinct: no duplicate error.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.0.100
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { .. }
        )));
    }

    #[test]
    fn hub_client_needs_its_own_public_key() {
        // The hub client sits between the nodes and the global clients.
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          ip: 10.100.49.10
        doorbell:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.11
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.1.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.publicKey",
            |e| matches!(e, ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Home.publicKey")
        ));
        assert!(error_at(
            &r,
            "clients.Phone.publicKey",
            |e| matches!(e, ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Home.hub.clients.doorbell.publicKey")
        ));
    }
}
