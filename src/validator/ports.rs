use std::collections::HashMap;

use crate::{
    config::{Config, Service},
    protocol::Protocol,
    types::{identifier::Identifier, port::PortOrRange},
    validator::types::{ConfigPath, ValidationError, ValidationReport},
};

#[derive(Default)]
struct PortRegistry {
    by_protocol: HashMap<Protocol, Vec<(PortOrRange, ConfigPath)>>,
}

const WG_PROTOCOLS: [Protocol; 1] = [Protocol::Udp];

impl PortRegistry {
    fn try_insert<'a>(
        &mut self,
        protocols: impl IntoIterator<Item = &'a Protocol>,
        port: PortOrRange,
        report: &mut ValidationReport,
        make_path: impl Fn() -> ConfigPath,
    ) {
        for protocol in protocols {
            let ports = self.by_protocol.entry(*protocol).or_default();

            let mut any_collision = false;

            for (existing_port, path) in ports.iter() {
                if port.conflicts(*existing_port) {
                    report.errors.push(ValidationError::PortCollision {
                        port,
                        at: make_path(),
                        with: path.clone(),
                    });
                    any_collision = true;
                }
            }

            if !any_collision {
                ports.push((port, make_path()));
            }
        }
    }

    fn insert<'a>(
        &mut self,
        protocols: impl IntoIterator<Item = &'a Protocol>,
        port: PortOrRange,
        make_path: impl Fn() -> ConfigPath,
    ) {
        for protocol in protocols {
            let ports = self.by_protocol.entry(*protocol).or_default();

            ports.push((port, make_path()))
        }
    }
}

fn add_external_service(
    service: &Service,
    port_registers: &mut HashMap<Identifier, PortRegistry>,
    report: &mut ValidationReport,
    make_path: impl Fn() -> ConfigPath,
) {
    let Some(wan) = &service.wan else { return };

    for via in &wan.via {
        let Some(ports) = port_registers.get_mut(via.node()) else {
            continue;
        };

        ports.try_insert(&service.proto, service.port.external(), report, &make_path);
    }
}

fn check_external_port_collisions(config: &Config, report: &mut ValidationReport) {
    let mut port_registers: HashMap<Identifier, PortRegistry> = config
        .nodes
        .iter()
        .filter_map(|(node_name, node)| {
            node.wan_zone.as_ref()?;

            let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

            let mut ports = PortRegistry::default();

            ports.insert(&WG_PROTOCOLS, node.listen_port.into(), || {
                make_path().extend(["listenPort"])
            });

            for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
                ports.insert(&WG_PROTOCOLS, vpn_interface.listen_port.into(), || {
                    make_path().extend(["vpnInterfaces", vpn_interface_name.as_ref(), "listenPort"])
                });
            }

            Some((node_name.clone(), ports))
        })
        .collect();

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

        for (service_name, service) in &node.services {
            add_external_service(service, &mut port_registers, report, || {
                make_path().extend(["services", service_name.as_ref(), "port"])
            });
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    add_external_service(service, &mut port_registers, report, || {
                        make_path().extend([
                            "vpnInterfaces",
                            vpn_interface_name.as_ref(),
                            "clients",
                            vpn_interface_client_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                            "port",
                        ])
                    });
                }
            }
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    add_external_service(service, &mut port_registers, report, || {
                        make_path().extend([
                            "zones",
                            zone_name.as_ref(),
                            "devices",
                            device_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                            "port",
                        ])
                    });
                }
            }
        }
    }

    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            add_external_service(service, &mut port_registers, report, || {
                ConfigPath::new([
                    "clients",
                    client_name.as_ref(),
                    "services",
                    service_name.as_ref(),
                    "port",
                ])
            });
        }
    }
}

fn check_internal_port_collisions(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        let mut ports = PortRegistry::default();

        for (service_name, service) in &client.services {
            ports.try_insert(&service.proto, service.port.internal(), report, || {
                ConfigPath::new([
                    "clients",
                    client_name.as_ref(),
                    "services",
                    service_name.as_ref(),
                    "port",
                ])
            });
        }
    }

    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name.as_ref()]);

        let mut node_ports = PortRegistry::default();
        node_ports.try_insert(&WG_PROTOCOLS, node.listen_port.into(), report, || {
            make_path().extend(["listenPort"])
        });

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                let mut ports = PortRegistry::default();

                for (service_name, service) in &device.services {
                    ports.try_insert(&service.proto, service.port.internal(), report, || {
                        make_path().extend([
                            "zones",
                            zone_name.as_ref(),
                            "devices",
                            device_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                            "port",
                        ])
                    });
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let make_path = || make_path().extend(["vpnInterfaces", vpn_interface_name.as_ref()]);

            node_ports.try_insert(
                &WG_PROTOCOLS,
                vpn_interface.listen_port.into(),
                report,
                || make_path().extend(["listenPort"]),
            );

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                let mut ports = PortRegistry::default();

                for (service_name, service) in &vpn_interface_client.services {
                    ports.try_insert(&service.proto, service.port.internal(), report, || {
                        make_path().extend([
                            "clients",
                            vpn_interface_client_name.as_ref(),
                            "services",
                            service_name.as_ref(),
                            "port",
                        ])
                    });
                }
            }
        }

        for (service_name, service) in &node.services {
            node_ports.try_insert(&service.proto, service.port.internal(), report, || {
                make_path().extend(["services", service_name.as_ref(), "port"])
            });
        }
    }
}

pub(super) fn check_ports(config: &Config, report: &mut ValidationReport) {
    check_external_port_collisions(config, report);
    check_internal_port_collisions(config, report);
}
