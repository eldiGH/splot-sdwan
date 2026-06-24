use std::{
    collections::{HashMap, hash_map::Entry},
    net::Ipv4Addr,
};

use crate::{
    config::{Config, ZoneOrVpnInterface},
    types::{
        config_location::{
            ClientIpLoc, ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, VpnClientLoc, VpnLoc,
            ZoneLoc,
        },
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

fn check_mesh_ips(config: &Config, report: &mut ValidationReport, networks: &mut Vec<Ipv4Network>) {
    if !add_network(config.mesh_network, networks, report, || {
        ConfigLocation::MeshNetwork
    }) {
        return;
    }

    for (client_name, client) in &config.clients {
        if let Some(mesh_ip) = client.mesh_ip
            && !config.mesh_network.contains(mesh_ip)
        {
            report.errors.push(ValidationError::IpOutsideSubnet {
                ip: mesh_ip,
                network: config.mesh_network,
                at: ConfigLocation::Client(client_name.clone(), ClientLoc::MeshIp),
            })
        }
    }

    for (node_name, node) in &config.nodes {
        if !config.mesh_network.contains(node.mesh_ip) {
            report.errors.push(ValidationError::IpOutsideSubnet {
                ip: node.mesh_ip,
                network: config.mesh_network,
                at: ConfigLocation::Node(node_name.clone(), NodeLoc::MeshIp),
            })
        }
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
                if !zone_network.contains(device.ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: device.ip,
                        network: zone_network,
                        at: ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::Zone(
                                zone_name.clone(),
                                ZoneLoc::Device(device_name.clone(), DeviceLoc::Ip),
                            ),
                        ),
                    })
                }
            }
        }
    }
}

fn check_vpn_interfaces_ips(
    config: &Config,
    report: &mut ValidationReport,
    networks: &mut Vec<Ipv4Network>,
) {
    for (node_name, node) in &config.nodes {
        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let vpn_interface_network = vpn_interface.address.network();

            if !add_network(vpn_interface_network, networks, report, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::VpnInterface(vpn_interface_name.clone(), VpnLoc::Address),
                )
            }) {
                continue;
            }

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                if !vpn_interface_network.contains(vpn_interface_client.ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: vpn_interface_client.ip,
                        network: vpn_interface_network,
                        at: ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::VpnInterface(
                                vpn_interface_name.clone(),
                                VpnLoc::Client(vpn_interface_client_name.clone(), VpnClientLoc::Ip),
                            ),
                        ),
                    })
                }
            }
        }
    }
}

fn check_clients_ips(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        for (node_name, node_networks) in &client.ips {
            let Some(node) = config.nodes.get(node_name) else {
                continue;
            };

            for (node_network_name, ip) in node_networks {
                let Some(node_network) = node
                    .network_by_name(node_network_name)
                    .map(|interface| interface.address().network())
                else {
                    continue;
                };

                if !node_network.contains(*ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: *ip,
                        network: node_network,
                        at: ConfigLocation::Client(
                            client_name.clone(),
                            ClientLoc::Ip(
                                node_name.clone(),
                                ClientIpLoc::Network(node_network_name.clone()),
                            ),
                        ),
                    });
                }
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

fn check_client_in_node_network_uniqueness(
    config: &Config,
    report: &mut ValidationReport,
    node_name: &Identifier,
    network_name: &Identifier,
    network_ips: &mut HashMap<Ipv4Addr, ConfigLocation>,
) {
    for (client_name, client) in &config.clients {
        let Some(ip) = client.network_by_name(node_name, network_name) else {
            continue;
        };

        try_insert_ip(
            network_ips,
            ip,
            report,
            ConfigLocation::Client(
                client_name.clone(),
                ClientLoc::Ip(
                    node_name.clone(),
                    ClientIpLoc::Network(network_name.clone()),
                ),
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

            check_client_in_node_network_uniqueness(
                config,
                report,
                node_name,
                zone_name,
                &mut zone_ips,
            );
        }
    }
}

fn check_vpn_interface_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let vpn_interface_ip = vpn_interface.address.ip();

            let mut vpn_interface_ips: HashMap<Ipv4Addr, ConfigLocation> = HashMap::new();
            vpn_interface_ips.insert(
                vpn_interface_ip,
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::VpnInterface(vpn_interface_name.clone(), VpnLoc::Address),
                ),
            );

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                try_insert_ip(
                    &mut vpn_interface_ips,
                    vpn_interface_client.ip,
                    report,
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::VpnInterface(
                            vpn_interface_name.clone(),
                            VpnLoc::Client(vpn_interface_client_name.clone(), VpnClientLoc::Ip),
                        ),
                    ),
                );
            }

            check_client_in_node_network_uniqueness(
                config,
                report,
                node_name,
                vpn_interface_name,
                &mut vpn_interface_ips,
            );
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
                if let Some(ZoneOrVpnInterface::Zone(_)) = node.network_by_name(network_name) {
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
    check_vpn_interfaces_ips(config, report, &mut networks);

    check_clients_ips(config, report);
    check_mesh_ip_uniqueness(config, report);
    check_zone_ip_uniqueness(config, report);
    check_vpn_interface_ip_uniqueness(config, report);

    check_client_zones(config, report);
}
