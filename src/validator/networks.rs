use std::{
    collections::{HashMap, hash_map::Entry},
    net::Ipv4Addr,
};

use crate::{
    config::Config,
    types::{
        config_location::{ClientIpLoc, ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, ZoneLoc},
        identifier::Identifier,
        ip::Ipv4Network,
    },
    validator::types::{ValidationError, ValidationReport},
};

fn add_network(
    network: Ipv4Network,
    networks: &mut Vec<Ipv4Network>,
    report: &mut ValidationReport,
    locate: impl Fn() -> ConfigLocation,
) -> bool {
    for existing_network in networks.iter() {
        if network.overlap(*existing_network) {
            report.errors.push(ValidationError::NetworkCollision {
                network,
                conflicting_with: *existing_network,
                at: locate(),
            });

            return false;
        }
    }

    networks.push(network);
    true
}

/// A host IP must lie inside its subnet and must not be the subnet's network or
/// broadcast address.
fn check_host_ip(
    ip: Ipv4Addr,
    network: Ipv4Network,
    report: &mut ValidationReport,
    locate: impl FnOnce() -> ConfigLocation,
) {
    if !network.contains(ip) {
        report.errors.push(ValidationError::IpOutsideSubnet {
            ip,
            network,
            at: locate(),
        });
    } else if let Some(kind) = network.reserved_address(ip) {
        report.errors.push(ValidationError::ReservedHostAddress {
            ip,
            network,
            kind,
            at: locate(),
        });
    }
}

fn check_mesh_ips(config: &Config, report: &mut ValidationReport, networks: &mut Vec<Ipv4Network>) {
    if !add_network(config.mesh_network, networks, report, || {
        ConfigLocation::MeshNetwork
    }) {
        return;
    }

    for (client_name, client) in &config.clients {
        if let Some(mesh_ip) = client.mesh_ip {
            check_host_ip(mesh_ip, config.mesh_network, report, || {
                ConfigLocation::Client(client_name.clone(), ClientLoc::MeshIp)
            });
        }
    }

    for (node_name, node) in &config.nodes {
        check_host_ip(node.mesh_ip, config.mesh_network, report, || {
            ConfigLocation::Node(node_name.clone(), NodeLoc::MeshIp)
        });
    }
}

fn check_zones_ips(
    config: &Config,
    report: &mut ValidationReport,
    networks: &mut Vec<Ipv4Network>,
) {
    for (node_name, node) in &config.nodes {
        for (zone_name, zone) in &node.zones {
            let zone_network = zone.address.network();

            if !add_network(zone_network, networks, report, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(zone_name.clone(), ZoneLoc::Address),
                )
            }) {
                continue;
            }

            for (device_name, device) in &zone.devices {
                check_host_ip(device.ip, zone_network, report, || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Zone(
                            zone_name.clone(),
                            ZoneLoc::Device(device_name.clone(), DeviceLoc::Ip),
                        ),
                    )
                });
            }
        }
    }
}

fn check_clients_ips(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        for (node_name, client_zones) in &client.ips {
            let Some(node) = config.nodes.get(node_name) else {
                continue;
            };

            for (zone_name, ip) in client_zones {
                let Some(zone) = node.zones.get(zone_name) else {
                    continue;
                };

                check_host_ip(*ip, zone.address.network(), report, || {
                    ConfigLocation::Client(
                        client_name.clone(),
                        ClientLoc::Ip(node_name.clone(), ClientIpLoc::Network(zone_name.clone())),
                    )
                });
            }
        }
    }
}

fn try_insert_ip(
    ips: &mut HashMap<Ipv4Addr, ConfigLocation>,
    ip: Ipv4Addr,
    report: &mut ValidationReport,
    at: ConfigLocation,
) {
    match ips.entry(ip) {
        Entry::Occupied(occ) => {
            report.errors.push(ValidationError::IpCollision {
                ip,
                at,
                with: occ.get().clone(),
            });
        }

        Entry::Vacant(vac) => {
            vac.insert(at);
        }
    }
}

fn check_client_in_zone_uniqueness(
    config: &Config,
    report: &mut ValidationReport,
    node_name: &Identifier,
    zone_name: &Identifier,
    zone_ips: &mut HashMap<Ipv4Addr, ConfigLocation>,
) {
    for (client_name, client) in &config.clients {
        let Some(ip) = client.ip_in_zone(node_name, zone_name) else {
            continue;
        };

        try_insert_ip(
            zone_ips,
            ip,
            report,
            ConfigLocation::Client(
                client_name.clone(),
                ClientLoc::Ip(node_name.clone(), ClientIpLoc::Network(zone_name.clone())),
            ),
        );
    }
}

fn check_mesh_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    let mut mesh_ips: HashMap<Ipv4Addr, ConfigLocation> = HashMap::new();

    for (client_name, client) in &config.clients {
        let Some(mesh_ip) = client.mesh_ip else {
            continue;
        };

        try_insert_ip(
            &mut mesh_ips,
            mesh_ip,
            report,
            ConfigLocation::Client(client_name.clone(), ClientLoc::MeshIp),
        );
    }

    for (node_name, node) in &config.nodes {
        try_insert_ip(
            &mut mesh_ips,
            node.mesh_ip,
            report,
            ConfigLocation::Node(node_name.clone(), NodeLoc::MeshIp),
        );
    }
}

fn check_zone_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        for (zone_name, zone) in &node.zones {
            let zone_ip = zone.address.ip();

            let mut zone_ips: HashMap<Ipv4Addr, ConfigLocation> = HashMap::new();
            zone_ips.insert(
                zone_ip,
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(zone_name.clone(), ZoneLoc::Address),
                ),
            );

            for (device_name, device) in &zone.devices {
                try_insert_ip(
                    &mut zone_ips,
                    device.ip,
                    report,
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Zone(
                            zone_name.clone(),
                            ZoneLoc::Device(device_name.clone(), DeviceLoc::Ip),
                        ),
                    ),
                );
            }

            check_client_in_zone_uniqueness(config, report, node_name, zone_name, &mut zone_ips);
        }
    }
}

fn check_client_zones(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        for (node_name, networks) in &client.ips {
            let Some(node) = config.nodes.get(node_name) else {
                continue;
            };

            let mut existing_zone: Option<ConfigLocation> = None;

            for network_name in networks.keys() {
                if node.zones.contains_key(network_name) {
                    let at = ConfigLocation::Client(
                        client_name.clone(),
                        ClientLoc::Ip(
                            node_name.clone(),
                            ClientIpLoc::Network(network_name.clone()),
                        ),
                    );

                    if let Some(existing_zone) = &existing_zone {
                        report.errors.push(ValidationError::NodeClientManyZones {
                            zone_name: network_name.clone(),
                            at,
                            existing_zone: existing_zone.clone(),
                        });
                    } else {
                        existing_zone = Some(at);
                    }
                }
            }
        }
    }
}

pub(super) fn check_networks(config: &Config, report: &mut ValidationReport) {
    let mut networks = Vec::new();
    check_mesh_ips(config, report, &mut networks);
    check_zones_ips(config, report, &mut networks);

    check_clients_ips(config, report);
    check_mesh_ip_uniqueness(config, report);
    check_zone_ip_uniqueness(config, report);

    check_client_zones(config, report);
}
