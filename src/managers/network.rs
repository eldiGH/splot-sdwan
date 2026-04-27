use std::net::Ipv4Addr;

use crate::{
    config::{Config, NodeVpnInterface},
    consts,
    managers::{UciManager, UciSectionBuilder},
    naming,
    types::ip::IpSubnet,
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "network";

struct WgInterface {
    name: String,
    private_key: String,
    listen_port: u16,
    addresses: Vec<IpSubnet>,

    clients: Vec<WgClient>,
}

impl WgInterface {
    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        let mut commands = UciSectionBuilder::new(FILE_NAME, &self.name, "interface")
            .set("proto", "wireguard")
            .set("private_key", &self.private_key)
            .set("listen_port", &self.listen_port.to_string())
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
    allowed_ips: Vec<IpSubnet>,
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

fn build_interfaces_from_node_vpn_interface(name: &str, node: &NodeVpnInterface) -> WgInterface {
    let mut clients = Vec::new();

    for (client_name, client) in &node.clients {
        clients.push(WgClient {
            description: client_name.clone(),
            allowed_ips: vec![IpSubnet::from_ip(client.ip, 32).unwrap()],
            public_key: client.public_key.clone(),
            route_allowed_ips: false,
            endpoint_host: None,
            endpoint_port: None,
        });
    }

    WgInterface {
        name: name.to_owned(),
        addresses: vec![node.address],
        listen_port: node.listen_port,
        private_key: "TODO".to_owned(),
        clients,
    }
}

fn build_interfaces_from_config(own_name: &str, config: &Config) -> Vec<WgInterface> {
    let own_node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    let mut clients = Vec::new();

    for (name, node) in &config.nodes {
        if name == own_name {
            continue;
        }

        let mut allowed_ips = vec![node.mesh_ip, node.lan.subnet];

        if let Some(vpn_interfaces) = &node.vpn_interfaces {
            allowed_ips.extend(vpn_interfaces.values().map(|i| i.address));
        }

        clients.push(WgClient {
            description: name.clone(),
            public_key: node.public_key.clone(),
            allowed_ips,
            route_allowed_ips: true,
            endpoint_host: Some(node.endpoint),
            endpoint_port: Some(node.listen_port),
        });
    }

    let mesh_interface = WgInterface {
        addresses: vec![own_node.mesh_ip],
        listen_port: own_node.listen_port,
        private_key: "TODO".to_owned(),
        name: consts::MESH_INTERFACE_RAW_NAME.to_owned(),
        clients,
    };

    let mut interfaces = vec![mesh_interface];

    if let Some(vpn_interfaces) = &own_node.vpn_interfaces {
        for (name, vpn_interface) in vpn_interfaces {
            interfaces.push(build_interfaces_from_node_vpn_interface(
                name,
                vpn_interface,
            ))
        }
    }

    interfaces
}

pub struct NetworkManager;

impl UciManager for NetworkManager {
    fn generate_commands(&self, config: &Config, own_name: &str) -> Vec<UciBatchCommand> {
        let interfaces = build_interfaces_from_config(own_name, config);

        let commands = interfaces.iter().flat_map(|i| i.to_uci_commands());

        commands.collect()
    }

    fn config_file(&self) -> &'static str {
        FILE_NAME
    }
}
