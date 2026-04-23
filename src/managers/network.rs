use std::net::Ipv4Addr;

use crate::{
    config::{Config, NodeHostedInterface},
    managers::{ManagerErrors, UciManager},
    types::ip::IpSubnet,
    uci::UciBatchCommand,
};

struct WgInterface {
    name: String,
    private_key: String,
    listen_port: u16,
    addresses: Vec<IpSubnet>,
    no_host_route: bool,
    multipath: bool,

    clients: Vec<WgClient>,
}

struct WgClient {
    description: String,
    public_key: String,
    allowed_ips: Vec<IpSubnet>,
    route_allowed_ips: bool,
    endpoint_host: Option<Ipv4Addr>,
    endpoint_port: Option<u16>,
}

fn build_interfaces_from_node_hosted_interface(
    name: &str,
    node: &NodeHostedInterface,
) -> WgInterface {
    let mut clients = Vec::new();

    for (client_name, client) in &node.clients {
        clients.push(WgClient {
            description: client_name.clone(),
            allowed_ips: vec![client.ip],
            public_key: client.public_key.clone(),
            route_allowed_ips: false,
            endpoint_host: None,
            endpoint_port: None,
        })
    }

    WgInterface {
        name: format!("spl_{}", name),
        addresses: vec![node.address],
        listen_port: node.listen_port,
        multipath: false,
        no_host_route: false,
        private_key: String::new(),
        clients,
    }
}

fn build_interfaces_from_config(
    own_name: &str,
    config: &Config,
) -> Result<Vec<WgInterface>, ManagerErrors> {
    let own_node = config
        .nodes
        .get(own_name)
        .ok_or(ManagerErrors::OwnNodeNotFound)?;

    let mut clients: Vec<WgClient> = Vec::new();

    for (name, node) in &config.nodes {
        if name == own_name {
            continue;
        }

        clients.push(WgClient {
            description: name.clone(),
            public_key: node.public_key.clone(),
            allowed_ips: vec![node.mesh_ip.clone(), node.lan_subnet.clone()],
            route_allowed_ips: false,
            endpoint_host: Some(node.endpoint),
            endpoint_port: Some(node.listen_port),
        })
    }

    let mesh_interface = WgInterface {
        addresses: vec![own_node.mesh_ip.clone()],
        listen_port: own_node.listen_port,
        multipath: false,
        no_host_route: false,
        private_key: String::new(),
        name: format!("spl_mesh_{}", own_name),
        clients,
    };

    let mut interfaces = vec![mesh_interface];

    if let Some(hosted_interfaces) = &own_node.hosted_interfaces {
        for (name, hosted_interface) in hosted_interfaces {
            interfaces.push(build_interfaces_from_node_hosted_interface(
                name,
                hosted_interface,
            ))
        }
    }

    Ok(interfaces)
}

fn get_interface_uci_create_commands(interface: &WgInterface) -> Vec<UciBatchCommand> {
    let mut commands: Vec<UciBatchCommand> = Vec::new();

    let interface_path = format!("network.{}", interface.name);

    commands.push(UciBatchCommand::set(interface_path.clone(), "interface"));

    let interface_path = interface_path;
    let prop = |name: &str| format!("{interface_path}.{name}");

    commands.push(UciBatchCommand::set(prop("proto"), "wireguard"));
    commands.push(UciBatchCommand::set(
        prop("private_key"),
        &interface.private_key,
    ));
    commands.push(UciBatchCommand::set(
        prop("listen_port"),
        interface.listen_port.to_string(),
    ));

    for address in &interface.addresses {
        commands.push(UciBatchCommand::add_list(
            prop("addresses"),
            address.to_string(),
        ));
    }

    commands.push(UciBatchCommand::set(
        prop("nohostroute"),
        if interface.no_host_route { "1" } else { "0" },
    ));

    commands.push(UciBatchCommand::set(
        prop("multipath"),
        if interface.multipath { "on" } else { "off" },
    ));

    let peer_config_name = format!("wireguard_{}", interface.name);
    for (i, client) in interface.clients.iter().enumerate() {
        let peer =
            |property_name: &str| format!("network.@{peer_config_name}[{i}].{property_name}");

        commands.push(UciBatchCommand::add("network", &peer_config_name));
        commands.push(UciBatchCommand::set(
            peer("description"),
            &client.description,
        ));
        commands.push(UciBatchCommand::set(peer("public_key"), &client.public_key));

        for ip in &client.allowed_ips {
            commands.push(UciBatchCommand::add_list(
                peer("allowed_ips"),
                ip.to_string(),
            ));
        }

        commands.push(UciBatchCommand::set(
            peer("route_allowed_ips"),
            if client.route_allowed_ips { "1" } else { "0" },
        ));

        if let Some(endpoint_host) = &client.endpoint_host {
            commands.push(UciBatchCommand::set(
                peer("endpoint_host"),
                endpoint_host.to_string(),
            ))
        }

        if let Some(endpoint_port) = &client.endpoint_port {
            commands.push(UciBatchCommand::set(
                peer("endpoint_port"),
                endpoint_port.to_string(),
            ))
        }

        commands.push(UciBatchCommand::set(peer("persistent_keepalive"), "25"))
    }

    commands
}

#[derive(Default)]
pub struct NetworkManager;

impl UciManager for NetworkManager {
    fn generate_commands(
        &self,
        config: &Config,
        own_name: &str,
    ) -> Result<Vec<UciBatchCommand>, ManagerErrors> {
        let interfaces = build_interfaces_from_config(own_name, config)?;

        let commands: Vec<UciBatchCommand> = interfaces
            .iter()
            .flat_map(get_interface_uci_create_commands)
            .collect();

        Ok(commands)
    }

    fn config_file(&self) -> &'static str {
        "network"
    }

    fn named_prefixes(&self) -> &'static [&'static str] {
        &["spl_"]
    }

    fn anonymous_prefixes(&self) -> &'static [&'static str] {
        &["wireguard_spl_"]
    }
}
