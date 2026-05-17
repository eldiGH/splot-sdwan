use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    config::{Config, ZoneOrVpnInterface},
    types::ip::Ipv4Network,
    validator::types::{ConfigPath, ValidationError, ValidationReport},
};

fn add_network(
    network: Ipv4Network,
    networks: &mut Vec<Ipv4Network>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) -> bool {
    for existing_network in networks.iter() {
        if network.overlap(*existing_network) {
            report.errors.push(ValidationError::NetworkCollision {
                network,
                conflicting_with: *existing_network,
                at: make_path(),
            });

            return false;
        }
    }

    networks.push(network);
    true
}

fn check_mesh_ips(config: &Config, report: &mut ValidationReport, networks: &mut Vec<Ipv4Network>) {
    if !add_network(config.mesh_network, networks, report, || {
        ConfigPath::new(["meshNetwork"])
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
                at: ConfigPath::new(["clients", client_name, "meshIp"]),
            })
        }
    }

    for (node_name, node) in &config.nodes {
        if !config.mesh_network.contains(node.mesh_ip) {
            report.errors.push(ValidationError::IpOutsideSubnet {
                ip: node.mesh_ip,
                network: config.mesh_network,
                at: ConfigPath::new(["nodes", node_name, "meshIp"]),
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
            let Some(zone_address) = zone.address else {
                continue;
            };
            let zone_network = zone_address.network();

            if !add_network(zone_network, networks, report, || {
                ConfigPath::new(["nodes", node_name, "zones", zone_name, "address"])
            }) {
                continue;
            }

            for (device_name, device) in &zone.devices {
                if !zone_network.contains(device.ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: device.ip,
                        network: zone_network,
                        at: ConfigPath::new([
                            "nodes",
                            node_name,
                            "zones",
                            zone_name,
                            "devices",
                            device_name,
                            "ip",
                        ]),
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
                ConfigPath::new([
                    "nodes",
                    node_name,
                    "vpnInterfaces",
                    vpn_interface_name,
                    "address",
                ])
            }) {
                continue;
            }

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                if !vpn_interface_network.contains(vpn_interface_client.ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: vpn_interface_client.ip,
                        network: vpn_interface_network,
                        at: ConfigPath::new([
                            "nodes",
                            node_name,
                            "vpnInterfaces",
                            vpn_interface_name,
                            "clients",
                            vpn_interface_client_name,
                            "ip",
                        ]),
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
                    .and_then(|interface| interface.address())
                    .map(|address| address.network())
                else {
                    continue;
                };

                if !node_network.contains(*ip) {
                    report.errors.push(ValidationError::IpOutsideSubnet {
                        ip: *ip,
                        network: node_network,
                        at: ConfigPath::new([
                            "clients",
                            client_name,
                            "ips",
                            node_name,
                            node_network_name,
                        ]),
                    });
                }
            }
        }
    }
}

fn check_client_in_node_network_uniqueness(
    config: &Config,
    report: &mut ValidationReport,
    node_name: &str,
    network_name: &str,
    network_ips: &mut HashMap<Ipv4Addr, ConfigPath>,
) {
    for (client_name, client) in &config.clients {
        let Some(ip) = client.network_by_name(node_name, network_name) else {
            continue;
        };

        let make_path =
            || ConfigPath::new(["clients", client_name, "ips", node_name, network_name]);

        if let Some(other_path) = network_ips.get(&ip) {
            report.errors.push(ValidationError::IpCollision {
                ip,
                at: make_path(),
                with: other_path.clone(),
            })
        } else {
            network_ips.insert(ip, make_path());
        }
    }
}

fn check_mesh_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    let mut mesh_ips: HashMap<Ipv4Addr, ConfigPath> = HashMap::new();

    for (client_name, client) in &config.clients {
        let Some(mesh_ip) = client.mesh_ip else {
            continue;
        };

        let make_path = || ConfigPath::new(["clients", client_name, "meshIp"]);

        if let Some(other_path) = mesh_ips.get(&mesh_ip) {
            report.errors.push(ValidationError::IpCollision {
                ip: mesh_ip,
                at: make_path(),
                with: other_path.clone(),
            });
        } else {
            mesh_ips.insert(mesh_ip, make_path());
        }
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name]);

        if let Some(other_path) = mesh_ips.get(&node.mesh_ip) {
            report.errors.push(ValidationError::IpCollision {
                ip: node.mesh_ip,
                at: make_path().extend(["meshIp"]),
                with: other_path.clone(),
            });
        } else {
            mesh_ips.insert(node.mesh_ip, make_path().extend(["meshIp"]));
        }
    }
}

fn check_zone_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        for (zone_name, zone) in &node.zones {
            let Some(zone_ip) = zone.address.map(|address| address.ip()) else {
                continue;
            };

            let make_path = || ConfigPath::new(["nodes", node_name, "zones", zone_name]);

            let mut zone_ips: HashMap<Ipv4Addr, ConfigPath> = HashMap::new();
            zone_ips.insert(zone_ip, make_path().extend(["address"]));

            for (device_name, device) in &zone.devices {
                let make_path = || make_path().extend(["devices", device_name, "ip"]);

                if let Some(other_path) = zone_ips.get(&device.ip) {
                    report.errors.push(ValidationError::IpCollision {
                        ip: device.ip,
                        at: make_path(),
                        with: other_path.clone(),
                    });
                } else {
                    zone_ips.insert(device.ip, make_path());
                };
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
            let make_path =
                || ConfigPath::new(["nodes", node_name, "vpnInterfaces", vpn_interface_name]);

            let mut vpn_interface_ips: HashMap<Ipv4Addr, ConfigPath> = HashMap::new();
            vpn_interface_ips.insert(vpn_interface_ip, make_path().extend(["address"]));

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                let make_path = || make_path().extend(["clients", vpn_interface_client_name, "ip"]);

                if let Some(other_path) = vpn_interface_ips.get(&vpn_interface_client.ip) {
                    report.errors.push(ValidationError::IpCollision {
                        ip: vpn_interface_client.ip,
                        at: make_path(),
                        with: other_path.clone(),
                    });
                } else {
                    vpn_interface_ips.insert(vpn_interface_client.ip, make_path());
                };
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

            let mut existing_zone: Option<ConfigPath> = None;

            for network_name in networks.keys() {
                let make_path =
                    || ConfigPath::new(["clients", client_name, "ips", node_name, network_name]);

                if let Some(network) = node.network_by_name(network_name)
                    && matches!(network, ZoneOrVpnInterface::Zone(_))
                {
                    if let Some(existing_zone) = &existing_zone {
                        report.errors.push(ValidationError::NodeClientManyZones {
                            zone_name: network_name.clone(),
                            at: make_path(),
                            existing_zone: existing_zone.clone(),
                        });
                    } else {
                        existing_zone = Some(make_path());
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
