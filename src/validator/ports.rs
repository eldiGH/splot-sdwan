use std::collections::HashMap;

use crate::{
    config::{Config, Service},
    protocol::Protocol,
    types::{
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, ServiceLoc, VpnClientLoc, VpnLoc,
            ZoneLoc,
        },
        identifier::Identifier,
        port::PortOrRange,
    },
    validator::types::{ValidationError, ValidationReport},
};

#[derive(Default)]
struct PortRegistry {
    by_protocol: HashMap<Protocol, Vec<(PortOrRange, ConfigLocation)>>,
}

const WG_PROTOCOLS: [Protocol; 1] = [Protocol::Udp];

impl PortRegistry {
    fn try_insert<'a>(
        &mut self,
        protocols: impl IntoIterator<Item = &'a Protocol>,
        port: PortOrRange,
        report: &mut ValidationReport,
        locate: impl Fn() -> ConfigLocation,
    ) {
        for protocol in protocols {
            let ports = self.by_protocol.entry(*protocol).or_default();

            let mut any_collision = false;

            for (existing_port, path) in ports.iter() {
                if port.conflicts(*existing_port) {
                    report.errors.push(ValidationError::PortCollision {
                        port,
                        at: locate(),
                        with: path.clone(),
                    });
                    any_collision = true;
                }
            }

            if !any_collision {
                ports.push((port, locate()));
            }
        }
    }

    fn insert<'a>(
        &mut self,
        protocols: impl IntoIterator<Item = &'a Protocol>,
        port: PortOrRange,
        locate: impl Fn() -> ConfigLocation,
    ) {
        for protocol in protocols {
            let ports = self.by_protocol.entry(*protocol).or_default();

            ports.push((port, locate()))
        }
    }
}

fn add_external_service(
    service: &Service,
    port_registers: &mut HashMap<Identifier, PortRegistry>,
    report: &mut ValidationReport,
    locate: impl Fn() -> ConfigLocation,
) {
    let Some(wan) = &service.wan else { return };

    for via in &wan.via {
        let Some(ports) = port_registers.get_mut(via.node()) else {
            continue;
        };

        ports.try_insert(&service.proto, service.port.external(), report, &locate);
    }
}

fn check_external_port_collisions(config: &Config, report: &mut ValidationReport) {
    let mut port_registers: HashMap<Identifier, PortRegistry> = config
        .nodes
        .iter()
        .filter_map(|(node_name, node)| {
            node.wan_zone.as_ref()?;

            let mut ports = PortRegistry::default();

            ports.insert(&WG_PROTOCOLS, node.listen_port.into(), || {
                ConfigLocation::Node(node_name.clone(), NodeLoc::ListenPort)
            });

            for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
                ports.insert(&WG_PROTOCOLS, vpn_interface.listen_port.into(), || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::VpnInterface(vpn_interface_name.clone(), VpnLoc::ListenPort),
                    )
                });
            }

            Some((node_name.clone(), ports))
        })
        .collect();

    for (node_name, node) in &config.nodes {
        for (service_name, service) in &node.services {
            add_external_service(service, &mut port_registers, report, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Service(service_name.clone(), ServiceLoc::Port),
                )
            });
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                for (service_name, service) in &vpn_interface_client.services {
                    add_external_service(service, &mut port_registers, report, || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::VpnInterface(
                                vpn_interface_name.clone(),
                                VpnLoc::Client(
                                    vpn_interface_client_name.clone(),
                                    VpnClientLoc::Service(service_name.clone(), ServiceLoc::Port),
                                ),
                            ),
                        )
                    });
                }
            }
        }

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    add_external_service(service, &mut port_registers, report, || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::Zone(
                                zone_name.clone(),
                                ZoneLoc::Device(
                                    device_name.clone(),
                                    DeviceLoc::Service(service_name.clone(), ServiceLoc::Port),
                                ),
                            ),
                        )
                    });
                }
            }
        }
    }

    for (client_name, client) in &config.clients {
        for (service_name, service) in &client.services {
            add_external_service(service, &mut port_registers, report, || {
                ConfigLocation::Client(
                    client_name.clone(),
                    ClientLoc::Service(service_name.clone(), ServiceLoc::Port),
                )
            });
        }
    }
}

fn check_internal_port_collisions(config: &Config, report: &mut ValidationReport) {
    for (client_name, client) in &config.clients {
        let mut ports = PortRegistry::default();

        for (service_name, service) in &client.services {
            ports.try_insert(&service.proto, service.port.internal(), report, || {
                ConfigLocation::Client(
                    client_name.clone(),
                    ClientLoc::Service(service_name.clone(), ServiceLoc::Port),
                )
            });
        }
    }

    for (node_name, node) in &config.nodes {
        let mut node_ports = PortRegistry::default();
        node_ports.try_insert(&WG_PROTOCOLS, node.listen_port.into(), report, || {
            ConfigLocation::Node(node_name.clone(), NodeLoc::ListenPort)
        });

        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                let mut ports = PortRegistry::default();

                for (service_name, service) in &device.services {
                    ports.try_insert(&service.proto, service.port.internal(), report, || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::Zone(
                                zone_name.clone(),
                                ZoneLoc::Device(
                                    device_name.clone(),
                                    DeviceLoc::Service(service_name.clone(), ServiceLoc::Port),
                                ),
                            ),
                        )
                    });
                }
            }
        }

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            node_ports.try_insert(
                &WG_PROTOCOLS,
                vpn_interface.listen_port.into(),
                report,
                || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::VpnInterface(vpn_interface_name.clone(), VpnLoc::ListenPort),
                    )
                },
            );

            for (vpn_interface_client_name, vpn_interface_client) in &vpn_interface.clients {
                let mut ports = PortRegistry::default();

                for (service_name, service) in &vpn_interface_client.services {
                    ports.try_insert(&service.proto, service.port.internal(), report, || {
                        ConfigLocation::Node(
                            node_name.clone(),
                            NodeLoc::VpnInterface(
                                vpn_interface_name.clone(),
                                VpnLoc::Client(
                                    vpn_interface_client_name.clone(),
                                    VpnClientLoc::Service(service_name.clone(), ServiceLoc::Port),
                                ),
                            ),
                        )
                    });
                }
            }
        }

        for (service_name, service) in &node.services {
            node_ports.try_insert(&service.proto, service.port.internal(), report, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Service(service_name.clone(), ServiceLoc::Port),
                )
            });
        }
    }
}

pub(super) fn check_ports(config: &Config, report: &mut ValidationReport) {
    check_external_port_collisions(config, report);
    check_internal_port_collisions(config, report);
}
