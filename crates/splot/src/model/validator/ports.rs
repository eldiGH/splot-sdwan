use std::collections::HashMap;

use crate::{
    config::{Config, Service},
    model::validator::types::{ValidationError, ValidationReport},
    types::{
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ServiceLoc,
            ZoneLoc,
        },
        identifier::Identifier,
        port::PortOrRange,
        protocol::Protocol,
    },
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

            Some((node_name.clone(), ports))
        })
        .collect();

    for (service, host) in config.services() {
        add_external_service(service, &mut port_registers, report, || {
            host.to_location(ServiceLoc::Port)
        });
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

        for (client_name, client) in node.hub_clients() {
            let mut ports = PortRegistry::default();

            for (service_name, service) in &client.services {
                ports.try_insert(&service.proto, service.port.internal(), report, || {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Hub(HubLoc::Client(
                            client_name.clone(),
                            HubClientLoc::Service(service_name.clone(), ServiceLoc::Port),
                        )),
                    )
                });
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

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::{HUB_HOME, types::ValidationError},
        test_support::{error_at, has_error, report},
    };

    #[test]
    fn ports_internal_collision_two_node_services() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: \"$node\"
      ssh2:
        port: 22
        proto: tcp
        allowFrom: \"$node\"
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_tcp_and_udp_same_number_ok() {
        // TCP 80 and UDP 80 on the same node don't collide.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        allowFrom: \"$node\"
      dns:
        port: 80
        proto: udp
        allowFrom: \"$node\"
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_external_collision() {
        // Two services both exposed externally on port 80/tcp via the same node.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      http1:
        port: 80
        proto: tcp
        wan:
          via: Home
      http2:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_node_listen_port_vs_external_udp_service() {
        // A UDP service exposed on the same external port as the node's WG listenPort.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      wg_clash:
        port: 51820
        proto: udp
        wan:
          via: Home
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn hub_client_service_ports_must_not_collide() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            http: {{ port: 80, proto: tcp, allowFrom: Home }}
            web: {{ port: 80, proto: tcp, allowFrom: Home }}
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.services.web.port",
            |e| matches!(e, ValidationError::PortCollision { .. })
        ));
    }
}
