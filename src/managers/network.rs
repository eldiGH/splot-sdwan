use std::{iter, net::Ipv4Addr};

use log::{debug, info};

use crate::{
    config::{Config, NodeVpnInterface},
    consts,
    managers::{UciManager, UciSectionBuilder},
    naming,
    types::ip::{Ipv4Interface, Ipv4Network},
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "network";

struct WgInterface {
    name: String,
    private_key: String,
    listen_port: u16,
    addresses: Vec<Ipv4Interface>,

    clients: Vec<WgClient>,
}

impl WgInterface {
    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        let mut commands = UciSectionBuilder::new(FILE_NAME, &self.name, "interface")
            .set("proto", "wireguard")
            .set("private_key", &self.private_key)
            .set("listen_port", self.listen_port.to_string())
            .extend_list(
                "address",
                self.addresses.iter().map(|address| address.to_string()),
            )
            .build();

        commands.extend(
            self.clients
                .iter()
                .flat_map(|c| c.to_uci_commands(&self.name)),
        );

        commands
    }
}

struct WgClient {
    description: String,
    public_key: String,
    allowed_ips: Vec<Ipv4Network>,
    route_allowed_ips: bool,
    endpoint_host: Option<Ipv4Addr>,
    endpoint_port: Option<u16>,
}

impl WgClient {
    fn to_uci_commands(&self, interface_name: &str) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(
            FILE_NAME,
            &self.description,
            &format!("wireguard_{}", naming::interface(interface_name)),
        )
        .set("description", naming::name_prefixed(&self.description))
        .set("public_key", &self.public_key)
        .set(
            "route_allowed_ips",
            if self.route_allowed_ips { "1" } else { "0" },
        )
        .set("persistent_keepalive", "25")
        .set_if_some(
            "endpoint_host",
            self.endpoint_host.map(|host| host.to_string()),
        )
        .set_if_some("endpoint_port", self.endpoint_port.map(|p| p.to_string()))
        .extend_list(
            "allowed_ips",
            self.allowed_ips.iter().map(|ip| ip.to_string()),
        )
        .build()
    }
}

fn build_vpn_interface(
    name: &str,
    node: &NodeVpnInterface,
    own_name: &str,
    config: &Config,
) -> WgInterface {
    let mut clients = Vec::new();

    for (client_name, client) in &node.clients {
        clients.push(WgClient {
            description: client_name.clone(),
            allowed_ips: vec![Ipv4Network::host(client.ip)],
            public_key: client.public_key.clone(),
            route_allowed_ips: false,
            endpoint_host: None,
            endpoint_port: None,
        });
    }

    clients.extend(config.clients.iter().filter_map(|(client_name, client)| {
        let public_key = client.public_key.as_ref()?;
        let networks = client.ips.get(own_name)?;
        let ip = networks.get(name)?;

        Some(WgClient {
            allowed_ips: vec![Ipv4Network::host(*ip)],
            description: client_name.to_owned(),
            endpoint_host: None,
            endpoint_port: None,
            public_key: public_key.to_owned(),
            route_allowed_ips: false,
        })
    }));

    WgInterface {
        name: name.to_owned(),
        addresses: vec![node.address],
        listen_port: node.listen_port,
        private_key: "TODO".to_owned(),
        clients,
    }
}

fn build_mesh_clients(config: &Config) -> Vec<WgClient> {
    config
        .clients
        .iter()
        .filter_map(|(client_name, client)| {
            let public_key = client.public_key.as_ref()?;
            let mesh_ip = client.mesh_ip.as_ref()?;

            Some(WgClient {
                description: client_name.to_owned(),
                public_key: public_key.to_owned(),
                allowed_ips: vec![Ipv4Network::host(*mesh_ip)],
                route_allowed_ips: false,
                endpoint_host: None,
                endpoint_port: None,
            })
        })
        .collect()
}

fn build_node_interfaces(own_name: &str, config: &Config) -> Vec<WgInterface> {
    info!("Generating network config for node '{own_name}'");

    let own_node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    let mut clients = Vec::new();

    for (node_name, node) in &config.nodes {
        if node_name == own_name {
            continue;
        }

        let allowed_ips: Vec<Ipv4Network> = iter::once(Ipv4Network::host(node.mesh_ip))
            .chain(
                node.zones
                    .values()
                    .filter_map(|zone| zone.address.map(|a| a.network())),
            )
            .chain(node.vpn_interfaces.values().map(|i| i.address.network()))
            .collect();

        debug!(
            "  Mesh peer '{}': endpoint {}:{}, {} AllowedIPs",
            node_name,
            node.endpoint,
            node.listen_port,
            allowed_ips.len()
        );

        clients.push(WgClient {
            description: node_name.clone(),
            public_key: node.public_key.clone(),
            allowed_ips,
            route_allowed_ips: true,
            endpoint_host: Some(node.endpoint),
            endpoint_port: Some(node.listen_port),
        });
    }

    clients.extend(build_mesh_clients(config));

    info!("  Mesh interface: {} peer(s)", clients.len());

    let mesh_interface = WgInterface {
        addresses: vec![
            Ipv4Interface::from_ip(own_node.mesh_ip, config.mesh_network.prefix())
                .expect("invalid prefix, should be validated"),
        ],
        listen_port: own_node.listen_port,
        private_key: "TODO".to_owned(),
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        clients,
    };

    let mut interfaces = vec![mesh_interface];

    for (vpn_interface_name, vpn_interface) in &own_node.vpn_interfaces {
        let wg_interface = build_vpn_interface(vpn_interface_name, vpn_interface, own_name, config);

        debug!(
            "  VPN interface '{vpn_interface_name}': {} client(s)",
            wg_interface.clients.len()
        );

        interfaces.push(wg_interface)
    }

    info!("  {} interface(s) total", interfaces.len());

    interfaces
}

pub struct NetworkManager;

impl UciManager for NetworkManager {
    fn generate_commands(&self, config: &Config, own_name: &str) -> Vec<UciBatchCommand> {
        let interfaces = build_node_interfaces(own_name, config);

        let commands = interfaces.iter().flat_map(|i| i.to_uci_commands());

        commands.collect()
    }

    fn config_file(&self) -> &'static str {
        FILE_NAME
    }
}
