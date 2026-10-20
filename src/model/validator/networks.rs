use std::{
    collections::{BTreeMap, BTreeSet, HashMap, hash_map::Entry},
    iter,
    net::Ipv4Addr,
};

use crate::{
    config::{self, Client, Config},
    model::{
        host::{Host, HostAddress, HostRef, Place, WgPeer},
        node::Node,
        validator::types::{ValidationError, ValidationReport},
    },
    types::{
        config_location::{
            ClientIpLoc, ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc,
            ZoneLoc,
        },
        identifier::Identifier,
        ip::{Ipv4Network, NotAHost},
    },
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

/// `ip` as an address on `network`, which lives at `place`. A host IP must lie
/// inside its subnet and must not be the subnet's network or broadcast address;
/// one that doesn't is reported and left out.
fn host_address(
    ip: Ipv4Addr,
    network: Ipv4Network,
    place: Place,
    report: &mut ValidationReport,
    locate: impl FnOnce() -> ConfigLocation,
) -> Option<HostAddress> {
    match network.host_interface(ip) {
        Ok(interface) => Some(HostAddress { interface, place }),
        Err(NotAHost::Outside) => {
            report.errors.push(ValidationError::IpOutsideSubnet {
                ip,
                network,
                at: locate(),
            });
            None
        }
        Err(NotAHost::Reserved(kind)) => {
            report.errors.push(ValidationError::ReservedHostAddress {
                ip,
                network,
                kind,
                at: locate(),
            });
            None
        }
    }
}

/// Builds every node and host while it checks their networks and addresses. The
/// hosts come in config order: each node, its devices zone by zone and its hub
/// clients, then the global clients. What fails a check is left out.
fn build(
    config: &Config,
    report: &mut ValidationReport,
) -> (BTreeMap<Identifier, Node>, Vec<Host>) {
    // The mesh space and every zone: none may overlap another.
    let mut networks = vec![config.mesh_network];
    let mut hub_networks = Vec::new();
    let mut nodes = BTreeMap::new();
    let mut hosts = Vec::new();

    for (node_name, node) in &config.nodes {
        let (built, node_hosts) = check_node(
            config,
            node_name,
            node,
            &mut networks,
            &mut hub_networks,
            report,
        );

        nodes.extend(built.map(|built| (node_name.clone(), built)));
        hosts.extend(node_hosts);
    }

    for (client_name, client) in &config.clients {
        hosts.push(client_host(config, client_name, client, report));
    }

    (nodes, hosts)
}

/// The node, and its hosts: the node itself, then its devices zone by zone, then
/// its hub clients. A node whose mesh IP fails its check is left out (its host
/// stays, for what's on its zones). A zone that overlaps another network is left
/// out, and its devices with it; so is a hub that fails its checks, but not its
/// clients.
fn check_node(
    config: &Config,
    node_name: &Identifier,
    node: &config::Node,
    networks: &mut Vec<Ipv4Network>,
    hub_networks: &mut Vec<Ipv4Network>,
    report: &mut ValidationReport,
) -> (Option<Node>, Vec<Host>) {
    let mut addresses = Vec::new();
    let mut zones = BTreeMap::new();
    let mut devices = Vec::new();

    let mesh = host_address(
        node.mesh_ip,
        config.mesh_network,
        Place::Mesh,
        report,
        || ConfigLocation::Node(node_name.clone(), NodeLoc::MeshIp),
    );
    addresses.extend(mesh.clone());

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

        let place = Place::Zone {
            node: node_name.clone(),
            zone: zone_name.clone(),
        };

        zones.insert(zone_name.clone(), zone_network);
        addresses.push(HostAddress {
            interface: zone.address,
            place: place.clone(),
        });

        for (device_name, device) in &zone.devices {
            let address = host_address(device.ip, zone_network, place.clone(), report, || {
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(
                        zone_name.clone(),
                        ZoneLoc::Device(device_name.clone(), DeviceLoc::Ip),
                    ),
                )
            });

            devices.push(Host {
                id: HostRef::Local {
                    node: node_name.clone(),
                    name: device_name.clone(),
                },
                addresses: address.into_iter().collect(),
                macs: device.macs.clone().into(),
                wg_peer: None,
            });
        }
    }

    let (hub, hub_clients) = check_hub(config, node_name, node, hub_networks, report);

    let built = mesh.map(|mesh| Node {
        name: node_name.clone(),
        public_key: node.public_key.clone(),
        psk: node.psk,
        endpoint: node.endpoint.clone(),
        listen_port: node.listen_port,
        mesh_address: mesh.interface,
        zones,
        hub,
        wan_zone: node.wan_zone.clone(),
    });
    let node_host = Host {
        id: HostRef::Node(node_name.clone()),
        addresses,
        macs: BTreeSet::new(),
        wg_peer: None,
    };
    let hosts = iter::once(node_host)
        .chain(devices)
        .chain(hub_clients)
        .collect();

    (built, hosts)
}

/// The node's hub network, if it passes its checks, and its hub clients. A hub
/// network lies inside the mesh space and overlaps no other hub; its clients' IPs
/// lie inside it. (Zones can't overlap the mesh space, so a hub can't overlap a
/// zone.)
fn check_hub(
    config: &Config,
    node_name: &Identifier,
    node: &config::Node,
    hub_networks: &mut Vec<Ipv4Network>,
    report: &mut ValidationReport,
) -> (Option<Ipv4Network>, Vec<Host>) {
    let Some(hub) = &node.hub else {
        return (None, Vec::new());
    };
    let at = || ConfigLocation::Node(node_name.clone(), NodeLoc::Hub(HubLoc::Network));

    let passed = if config.mesh_network.contains_network(hub.network) {
        add_network(hub.network, hub_networks, report, at)
    } else {
        report.errors.push(ValidationError::HubOutsideMeshNetwork {
            network: hub.network,
            mesh_network: config.mesh_network,
            at: at(),
        });
        false
    };

    let mut clients = Vec::new();

    for (client_name, client) in &hub.clients {
        let place = Place::Hub {
            node: node_name.clone(),
        };
        let address = host_address(client.ip, hub.network, place, report, || {
            ConfigLocation::Node(
                node_name.clone(),
                NodeLoc::Hub(HubLoc::Client(client_name.clone(), HubClientLoc::Ip)),
            )
        });

        clients.push(Host {
            id: HostRef::Local {
                node: node_name.clone(),
                name: client_name.clone(),
            },
            addresses: address.into_iter().collect(),
            macs: BTreeSet::new(),
            wg_peer: Some(WgPeer {
                public_key: client.public_key.clone(),
                psk: client.psk,
            }),
        });
    }

    (passed.then_some(hub.network), clients)
}

/// A global client: its mesh IP, and its IP on each zone it's on.
fn client_host(
    config: &Config,
    client_name: &Identifier,
    client: &Client,
    report: &mut ValidationReport,
) -> Host {
    let mut addresses = Vec::new();

    if let Some(mesh_ip) = client.mesh_ip {
        addresses.extend(host_address(
            mesh_ip,
            config.mesh_network,
            Place::Mesh,
            report,
            || ConfigLocation::Client(client_name.clone(), ClientLoc::MeshIp),
        ));
    }

    for (node_name, client_zones) in &client.ips {
        // An unknown node or zone is the entities pass's error.
        let Some(node) = config.nodes.get(node_name) else {
            continue;
        };

        for (zone_name, ip) in client_zones {
            let Some(zone) = node.zones.get(zone_name) else {
                continue;
            };
            let place = Place::Zone {
                node: node_name.clone(),
                zone: zone_name.clone(),
            };

            addresses.extend(host_address(
                *ip,
                zone.address.network(),
                place,
                report,
                || {
                    ConfigLocation::Client(
                        client_name.clone(),
                        ClientLoc::Ip(node_name.clone(), ClientIpLoc::Network(zone_name.clone())),
                    )
                },
            ));
        }
    }

    Host {
        id: HostRef::Client(client_name.clone()),
        addresses,
        macs: client.macs.clone().into(),
        wg_peer: client.public_key.clone().map(|public_key| WgPeer {
            public_key,
            psk: client.psk,
        }),
    }
}

/// One address, one path: every other node routes a hub network to its node as a
/// whole, so no node or global client can have its mesh IP inside one.
fn check_mesh_ips_outside_hubs(config: &Config, report: &mut ValidationReport) {
    let hubs: Vec<(Ipv4Network, ConfigLocation)> = config
        .nodes
        .iter()
        .filter_map(|(node_name, node)| {
            let hub = node.hub.as_ref()?;
            let at = ConfigLocation::Node(node_name.clone(), NodeLoc::Hub(HubLoc::Network));

            Some((hub.network, at))
        })
        .collect();

    let nodes_mesh_ips = config.nodes.iter().map(|(node_name, node)| {
        let at = ConfigLocation::Node(node_name.clone(), NodeLoc::MeshIp);

        (node.mesh_ip, at)
    });
    let clients_mesh_ips = config.clients.iter().filter_map(|(client_name, client)| {
        let at = ConfigLocation::Client(client_name.clone(), ClientLoc::MeshIp);

        Some((client.mesh_ip?, at))
    });

    for (ip, at) in nodes_mesh_ips.chain(clients_mesh_ips) {
        for (network, hub) in &hubs {
            if network.contains(ip) {
                report.errors.push(ValidationError::MeshIpInHubNetwork {
                    ip,
                    hub: hub.clone(),
                    at: at.clone(),
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

fn check_hub_ip_uniqueness(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        let Some(hub) = &node.hub else { continue };
        let mut hub_ips: HashMap<Ipv4Addr, ConfigLocation> = HashMap::new();

        for (client_name, client) in &hub.clients {
            try_insert_ip(
                &mut hub_ips,
                client.ip,
                report,
                ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Hub(HubLoc::Client(client_name.clone(), HubClientLoc::Ip)),
                ),
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

/// Checks every network and address, and builds the nodes and hosts from those
/// that pass.
pub(super) fn check_networks(
    config: &Config,
    report: &mut ValidationReport,
) -> (BTreeMap<Identifier, Node>, Vec<Host>) {
    let (nodes, hosts) = build(config, report);
    check_mesh_ips_outside_hubs(config, report);

    check_mesh_ip_uniqueness(config, report);
    check_zone_ip_uniqueness(config, report);
    check_hub_ip_uniqueness(config, report);

    check_client_zones(config, report);

    (nodes, hosts)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        model::validator::HUB_HOME,
        test_support::{config, error_at, has_error, report},
        types::ip::ReservedAddress,
    };

    fn ips(host: &Host) -> Vec<Ipv4Addr> {
        host.addresses.iter().map(HostAddress::ip).collect()
    }

    #[test]
    fn what_fails_a_check_is_left_out_of_the_hosts() {
        // The printer is outside its zone. Shop (sorting after lan) overlaps lan, so
        // it's left out, and its scanner with it.
        let config = config(
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
        devices:
          printer: { ip: 192.168.2.50, macs: AA:BB:CC:DD:EE:01 }
      shop:
        address: 192.168.1.129/25
        devices:
          scanner: { ip: 192.168.1.130, macs: AA:BB:CC:DD:EE:02 }
",
        );
        let mut report = ValidationReport::default();
        let (nodes, hosts) = check_networks(&config, &mut report);

        assert_eq!(report.errors.len(), 2);
        let [home, printer] = hosts.as_slice() else {
            panic!("expected Home and its printer, got {}", hosts.len());
        };
        assert_eq!(
            ips(home),
            ["10.100.0.1", "192.168.1.1"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
        assert!(ips(printer).is_empty());
        // The node keeps lan only.
        let networks: Vec<String> = nodes[&"Home".parse::<Identifier>().unwrap()]
            .networks()
            .map(|network| network.to_string())
            .collect();
        assert_eq!(networks, ["192.168.1.0/24"]);
    }

    #[test]
    fn a_node_whose_mesh_ip_or_hub_fails_its_check_is_left_out_or_loses_the_hub() {
        // Cabin's mesh IP lies outside the mesh: no node. Home's hub lies outside
        // the mesh: Home without a hub.
        let config = config(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: 10.200.49.0/24
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.200.0.2
",
        );
        let mut report = ValidationReport::default();
        let (nodes, _) = check_networks(&config, &mut report);

        assert_eq!(report.errors.len(), 2);
        let names: Vec<String> = nodes.keys().map(ToString::to_string).collect();
        assert_eq!(names, ["Home"]);
        assert_eq!(nodes.values().next().unwrap().networks().count(), 0);
    }

    #[test]
    fn networks_collision_mesh_and_zone_overlap() {
        // Zone 192.168.1.0/24 overlaps with meshNetwork 192.168.1.0/24.
        let r = report(
            "
meshNetwork: 192.168.1.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 192.168.1.1
    zones:
      lan:
        address: 192.168.1.2/24
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    #[test]
    fn networks_collision_zone_zone() {
        // Two zones with the same subnet.
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
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.1.1/24
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    #[test]
    fn networks_ip_outside_mesh_subnet() {
        // Node meshIp 10.200.0.1 is outside meshNetwork 10.100.0.0/24.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.200.0.1
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::IpOutsideSubnet { .. }
        )));
    }

    #[test]
    fn networks_ip_outside_zone_subnet() {
        // Device IP 192.168.2.50 is outside its zone 192.168.1.0/24.
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
        devices:
          printer:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:FF
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.zones.lan.devices.printer.ip",
            |e| matches!(e, ValidationError::IpOutsideSubnet { .. })
        ));
    }

    #[test]
    fn networks_ip_collision_two_nodes_same_mesh_ip() {
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
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::IpCollision { .. }
        )));
    }

    #[test]
    fn networks_client_many_zones() {
        // Client with IPs on two zone networks of the same node (max one allowed).
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
      guest:
        address: 192.168.2.1/24
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
        guest: 192.168.2.50
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NodeClientManyZones { .. }
        )));
    }

    // A host IP must not be its subnet's network or broadcast address. Such an IP
    // used to pass validation and then panic in the generators. The fixture puts
    // all five kinds of host IP on reserved addresses; the two tests swap which
    // ones get the network address and which the broadcast address.
    fn reserved_fixture(
        node_mesh_ip: &str,
        client_mesh_ip: &str,
        device_ip: &str,
        hub_client_ip: &str,
        client_zone_ip: &str,
    ) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: {node_mesh_ip}
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: {device_ip}
            macs: AA:BB:CC:DD:EE:01
      iot:
        address: 192.168.2.1/24
    hub:
      network: 10.100.0.128/26
      clients:
        camera:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: {hub_client_ip}
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: {client_mesh_ip}
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home:
        iot: {client_zone_ip}
"
        )
    }

    fn reserved_at(r: &ValidationReport, path: &str, expected: ReservedAddress) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::ReservedHostAddress { kind, .. } if *kind == expected),
        )
    }

    const NODE_MESH_IP: &str = "nodes.Home.meshIp";
    const CLIENT_MESH_IP: &str = "clients.Phone.meshIp";
    const DEVICE_IP: &str = "nodes.Home.zones.lan.devices.printer.ip";
    const HUB_CLIENT_IP: &str = "nodes.Home.hub.clients.camera.ip";
    const CLIENT_ZONE_IP: &str = "clients.Phone.ips.Home.iot";

    #[test]
    fn networks_host_ip_on_network_address() {
        let r = report(&reserved_fixture(
            "10.100.0.0",
            "10.100.0.255",
            "192.168.1.0",
            "10.100.0.128",
            "192.168.2.0",
        ));
        assert!(reserved_at(&r, NODE_MESH_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, CLIENT_MESH_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, DEVICE_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, HUB_CLIENT_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, CLIENT_ZONE_IP, ReservedAddress::Network));
    }

    #[test]
    fn networks_host_ip_on_broadcast_address() {
        let r = report(&reserved_fixture(
            "10.100.0.255",
            "10.100.0.0",
            "192.168.1.255",
            "10.100.0.191",
            "192.168.2.255",
        ));
        assert!(reserved_at(&r, NODE_MESH_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, CLIENT_MESH_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, DEVICE_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, HUB_CLIENT_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, CLIENT_ZONE_IP, ReservedAddress::Broadcast));
    }

    #[test]
    fn networks_host_ips_ordinary_addresses_are_fine() {
        // Same fixture, every IP an ordinary host address: no reserved-address error.
        let r = report(&reserved_fixture(
            "10.100.0.1",
            "10.100.0.100",
            "192.168.1.50",
            "10.100.0.130",
            "192.168.2.60",
        ));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::ReservedHostAddress { .. }
        )));
    }

    #[test]
    fn networks_slash_31_has_no_reserved_addresses() {
        // RFC 3021: both addresses of a /31 are usable host addresses.
        let r = report(
            "
meshNetwork: 10.100.0.0/31
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.0
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        assert!(
            r.errors.is_empty(),
            "unexpected errors: {:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn hub_network_must_lie_inside_the_mesh_network() {
        for network in ["10.200.49.0/24", "10.0.0.0/8", "10.100.0.0/15"] {
            // The last two hold the mesh network rather than lie inside it.
            let r = report(&format!(
                "{HUB_HOME}
    hub:
      network: {network}
"
            ));
            assert!(
                error_at(&r, "nodes.Home.hub.network", |e| matches!(
                    e,
                    ValidationError::HubOutsideMeshNetwork { .. }
                )),
                "{network}"
            );
        }

        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
"
        ));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::HubOutsideMeshNetwork { .. }
        )));
    }

    fn two_hubs(alpha_hub: &str, zeta_hub: &str) -> ValidationReport {
        report(&format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Alpha:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: {alpha_hub}
  Zeta:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    hub:
      network: {zeta_hub}
"
        ))
    }

    #[test]
    fn hub_networks_must_not_overlap() {
        // Both ways round: the bigger network on the node checked first, then
        // on the one checked second.
        for (alpha, zeta) in [
            ("10.100.48.0/22", "10.100.49.0/24"),
            ("10.100.49.0/24", "10.100.48.0/22"),
        ] {
            let r = two_hubs(alpha, zeta);
            assert!(
                error_at(&r, "nodes.Zeta.hub.network", |e| matches!(
                    e,
                    ValidationError::NetworkCollision { .. }
                )),
                "{alpha} vs {zeta}"
            );
        }
    }

    #[test]
    fn separate_hub_networks_are_fine() {
        let r = two_hubs("10.100.49.0/24", "10.100.84.0/24");
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    fn mesh_ip_in_hub(r: &ValidationReport, path: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::MeshIpInHubNetwork { hub, .. } if hub.to_string() == "nodes.Home.hub.network"),
        )
    }

    #[test]
    fn mesh_ips_must_not_lie_inside_a_hub_network() {
        // One address, one path: a hub network is routed to its node as a whole.
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
  Cabin:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.49.2
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.49.100
"
        ));
        assert!(mesh_ip_in_hub(&r, "nodes.Cabin.meshIp"));
        assert!(mesh_ip_in_hub(&r, "clients.Phone.meshIp"));
        assert!(!mesh_ip_in_hub(&r, "nodes.Home.meshIp"));
    }

    #[test]
    fn own_mesh_ip_must_not_lie_inside_own_hub_network() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.0.0/24
"
        ));
        assert!(mesh_ip_in_hub(&r, "nodes.Home.meshIp"));
    }

    #[test]
    fn hub_client_ip_must_lie_inside_its_hub_network() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.50.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.ip",
            |e| matches!(e, ValidationError::IpOutsideSubnet { .. })
        ));
    }

    #[test]
    fn hub_client_ips_are_unique() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        a-cam:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
        b-cam:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: 10.100.49.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.b-cam.ip",
            |e| matches!(e, ValidationError::IpCollision { with, .. } if with.to_string() == "nodes.Home.hub.clients.a-cam.ip")
        ));
    }
}
