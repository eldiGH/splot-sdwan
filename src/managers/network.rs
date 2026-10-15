use std::{iter, net::Ipv4Addr};

use log::{debug, info};

use crate::{
    config::{Config, NodeVpnInterface},
    consts,
    managers::{
        NodeContext, UciManager, UciSection, UciSectionBuilder,
        naming::{self, UciSectionName},
    },
    types::{
        identifier::Identifier,
        ip::{Ipv4Interface, Ipv4Network},
        port::Port,
        wg_key::WgPublicKey,
    },
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "network";

struct WgInterface {
    name: String,
    private_key: String,
    listen_port: Port,
    addresses: Vec<Ipv4Interface>,

    clients: Vec<WgClient>,
}

impl UciSection for WgInterface {
    const FILE: &'static str = FILE_NAME;

    fn section_type(&self) -> &str {
        "interface"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.name.as_str()]
    }

    /// Not `spl_interface_<name>`: an interface's section name is the interface
    /// name itself. Zones and peer section types refer to it, and netifd names the
    /// WireGuard device after it (at most 15 characters).
    fn section_name(&self) -> UciSectionName {
        naming::interface(&self.name)
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("proto", "wireguard")
            .set("private_key", &self.private_key)
            .set("listen_port", self.listen_port.to_string())
            .extend_list("address", &self.addresses)
    }
}

struct WgClient {
    description: String,
    public_key: WgPublicKey,
    allowed_ips: Vec<Ipv4Network>,
    route_allowed_ips: bool,
    endpoint_host: Option<Ipv4Addr>,
    endpoint_port: Option<Port>,
}

/// A client as a uci peer section. Its section type names the interface it
/// belongs to (`wireguard_<interface>`), which the client itself doesn't know.
struct PeerSection<'a> {
    section_type: &'a str,
    client: &'a WgClient,
}

impl UciSection for PeerSection<'_> {
    const FILE: &'static str = FILE_NAME;

    fn section_type(&self) -> &str {
        self.section_type
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.client.description.as_str()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let client = self.client;

        section
            .set("description", naming::name_prefixed(&client.description))
            .set("public_key", client.public_key.as_str())
            .set(
                "route_allowed_ips",
                if client.route_allowed_ips { "1" } else { "0" },
            )
            .set("persistent_keepalive", "25")
            .set_if_some(
                "endpoint_host",
                client.endpoint_host.map(|host| host.to_string()),
            )
            .set_if_some("endpoint_port", client.endpoint_port.map(|p| p.to_string()))
            .extend_list("allowed_ips", &client.allowed_ips)
    }
}

/// An interface's section, followed by one section per peer.
fn interface_commands(interface: &WgInterface) -> Vec<UciBatchCommand> {
    let peer_type = format!("wireguard_{}", interface.section_name());

    let mut commands = interface.to_uci_commands();
    for client in &interface.clients {
        let peer = PeerSection {
            section_type: &peer_type,
            client,
        };
        commands.extend(peer.to_uci_commands());
    }

    commands
}

fn build_vpn_interface(
    name: &Identifier,
    node: &NodeVpnInterface,
    node_context: &NodeContext,
    config: &Config,
) -> WgInterface {
    let mut clients = Vec::new();

    for (client_name, client) in &node.clients {
        clients.push(WgClient {
            description: client_name.to_string(),
            allowed_ips: vec![Ipv4Network::host(client.ip)],
            public_key: client.public_key.clone(),
            route_allowed_ips: false,
            endpoint_host: None,
            endpoint_port: None,
        });
    }

    clients.extend(config.clients.iter().filter_map(|(client_name, client)| {
        let public_key = client.public_key.as_ref()?;
        let networks = client.ips.get(node_context.own_name)?;
        let ip = networks.get(name)?;

        Some(WgClient {
            allowed_ips: vec![Ipv4Network::host(*ip)],
            description: client_name.to_string(),
            endpoint_host: None,
            endpoint_port: None,
            public_key: public_key.clone(),
            route_allowed_ips: false,
        })
    }));

    let private_key = node_context
        .splot_config
        .vpn_interface_keys()
        .get(name)
        .expect("private key was already ensured");

    WgInterface {
        name: name.to_string(),
        addresses: vec![node.address],
        listen_port: node.listen_port,
        private_key: private_key.clone(),
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
                description: client_name.to_string(),
                public_key: public_key.clone(),
                allowed_ips: vec![Ipv4Network::host(*mesh_ip)],
                route_allowed_ips: false,
                endpoint_host: None,
                endpoint_port: None,
            })
        })
        .collect()
}

fn build_node_interfaces(node_context: &NodeContext, config: &Config) -> Vec<WgInterface> {
    info!(
        "Generating network config for node '{}'",
        node_context.own_name
    );

    let mut clients = Vec::new();

    for (node_name, node) in &config.nodes {
        if node_name == node_context.own_name {
            continue;
        }

        let allowed_ips: Vec<Ipv4Network> = iter::once(Ipv4Network::host(node.mesh_ip))
            .chain(node.zones.values().map(|zone| zone.address.network()))
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
            description: node_name.to_string(),
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
            Ipv4Interface::from_ip(node_context.own_node.mesh_ip, config.mesh_network.prefix())
                .expect("invalid prefix, should be validated"),
        ],
        listen_port: node_context.own_node.listen_port,
        private_key: node_context.splot_config.mesh_key().to_owned(),
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        clients,
    };

    let mut interfaces = vec![mesh_interface];

    for (vpn_interface_name, vpn_interface) in &node_context.own_node.vpn_interfaces {
        let wg_interface =
            build_vpn_interface(vpn_interface_name, vpn_interface, node_context, config);

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
    fn generate_commands(
        &self,
        config: &Config,
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand> {
        let interfaces = build_node_interfaces(node_context, config);

        interfaces.iter().flat_map(interface_commands).collect()
    }

    fn config_file(&self) -> &'static str {
        FILE_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{splot_config::SplotConfig, test_support::config, uci::UciBatchCommand};

    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    vpnInterfaces:
      vpn_a:
        listenPort: 51821
        address: 10.8.1.1/24
        clients: {}
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
";

    fn has_cmd(cmds: &[UciBatchCommand], s: &str) -> bool {
        cmds.iter().any(|c| c.to_string().contains(s))
    }

    const MESH_KEY: &str = "MESH_PRIVATE_AAAA";
    const VPN_A_KEY: &str = "VPN_A_PRIVATE_BBBB";

    fn cmds() -> Vec<UciBatchCommand> {
        let cfg = config(FIXTURE);
        let own_name: Identifier = "Home".parse().unwrap();
        let splot_config = SplotConfig::for_tests(MESH_KEY, &[("vpn_a", VPN_A_KEY)]);

        NetworkManager.generate_commands(
            &cfg,
            &NodeContext {
                own_node: cfg.nodes.get(&own_name).unwrap(),
                own_name: &own_name,
                splot_config: &splot_config,
            },
        )
    }

    #[test]
    fn mesh_interface_section_present() {
        assert!(has_cmd(&cmds(), "network.spl_mesh='interface'"));
    }

    #[test]
    fn mesh_interface_has_wireguard_proto() {
        assert!(has_cmd(&cmds(), "spl_mesh.proto='wireguard'"));
    }

    #[test]
    fn remote_node_peer_section_present() {
        // Cabin is a remote mesh peer → peer section on the mesh interface, with
        // wireguard_spl_mesh type, which also leads its name.
        assert!(has_cmd(
            &cmds(),
            "network.spl_wireguard_spl_mesh_Cabin='wireguard_spl_mesh'"
        ));
    }

    #[test]
    fn vpn_interface_section_present() {
        assert!(has_cmd(&cmds(), "network.spl_vpn_a='interface'"));
    }

    #[test]
    fn mesh_interface_uses_mesh_private_key() {
        let c = cmds();
        assert!(has_cmd(&c, &format!("spl_mesh.private_key='{MESH_KEY}'")));
        assert!(!has_cmd(&c, &format!("spl_mesh.private_key='{VPN_A_KEY}'")));
    }

    #[test]
    fn vpn_interface_uses_own_private_key() {
        let c = cmds();
        assert!(has_cmd(&c, &format!("spl_vpn_a.private_key='{VPN_A_KEY}'")));
        assert!(!has_cmd(&c, &format!("spl_vpn_a.private_key='{MESH_KEY}'")));
    }

    fn cmds_for(yaml: &str, vpn_interfaces: &[&str]) -> Vec<UciBatchCommand> {
        let cfg = config(yaml);
        let own_name: Identifier = "Home".parse().unwrap();
        let keys: Vec<(&str, &str)> = vpn_interfaces
            .iter()
            .map(|name| (*name, VPN_A_KEY))
            .collect();
        let splot_config = SplotConfig::for_tests(MESH_KEY, &keys);

        NetworkManager.generate_commands(
            &cfg,
            &NodeContext {
                own_node: cfg.nodes.get(&own_name).unwrap(),
                own_name: &own_name,
                splot_config: &splot_config,
            },
        )
    }

    #[test]
    fn same_client_on_mesh_and_vpn_interface_gets_two_peer_sections() {
        // Phone is a mesh peer (meshIp) and a peer on Home's `guests` interface.
        // Both peer sections used to be named `spl_Phone`, and uci merged them into
        // one `guests` peer: the mesh peer silently disappeared.
        let c = cmds_for(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    vpnInterfaces:
      guests:
        listenPort: 51821
        address: 10.8.0.1/24
        clients: {}
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    ips:
      Home:
        guests: 10.8.0.5
",
            &["guests"],
        );
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_Phone='wireguard_spl_mesh'"
        ));
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_guests_Phone='wireguard_spl_guests'"
        ));
        assert!(!has_cmd(&c, "set network.spl_Phone="));
        assert!(crate::pipeline::find_duplicate_sections(&c).is_empty());
    }

    #[test]
    fn hyphenated_vpn_interface_gets_valid_names_everywhere() {
        // uci rejects '-' in section names; the interface, and the peer type that
        // has to match it (`wireguard_<interface>`), both use the mapped name.
        let c = cmds_for(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    vpnInterfaces:
      guest-wifi:
        listenPort: 51821
        address: 10.8.0.1/24
        clients:
          old-laptop:
            publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
            ip: 10.8.0.2
",
            &["guest-wifi"],
        );
        assert!(has_cmd(&c, "set network.spl_guest_wifi='interface'"));
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_guest_wifi_old_laptop='wireguard_spl_guest_wifi'"
        ));
        // No section or section type anywhere contains a hyphen.
        for command in &c {
            if let UciBatchCommand::Set(path, value) = command
                && path.matches('.').count() == 1
            {
                assert!(!path.contains('-') && !value.contains('-'), "{command}");
            }
        }
    }
}
