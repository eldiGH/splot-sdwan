use std::{iter, net::Ipv4Addr};

use log::{debug, info};

use crate::{
    consts,
    managers::{
        NodeContext, UciManager, UciSection, UciSectionBuilder,
        naming::{self, UciSectionName},
    },
    model::{Network, host::Place},
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
            // Not `address`: OpenWrt's WireGuard handler reads `addresses`.
            .extend_list("addresses", &self.addresses)
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

/// A peer for every other node: its endpoint, and its mesh IP and everything
/// behind it.
fn build_node_peers(network: &Network, own_name: &Identifier) -> Vec<WgClient> {
    let mut peers = Vec::new();

    for (node_name, node) in network.nodes() {
        if node_name == own_name {
            continue;
        }

        // Its hub network too, even while the hub has no clients.
        let allowed_ips: Vec<Ipv4Network> = iter::once(Ipv4Network::host(node.mesh_address().ip()))
            .chain(node.networks())
            .collect();

        debug!(
            "  Mesh peer '{}': endpoint {}:{}, {} AllowedIPs",
            node_name,
            node.endpoint(),
            node.listen_port(),
            allowed_ips.len()
        );

        peers.push(WgClient {
            description: node_name.to_string(),
            public_key: node.public_key().clone(),
            allowed_ips,
            route_allowed_ips: true,
            endpoint_host: Some(node.endpoint()),
            endpoint_port: Some(node.listen_port()),
        });
    }

    peers
}

/// A peer for each host with a key and an address `on` picks: global clients on
/// the mesh, or this node's hub clients.
fn build_client_peers(network: &Network, on: impl Fn(&Place) -> bool) -> Vec<WgClient> {
    network
        .hosts()
        .iter()
        .filter_map(|host| {
            let public_key = host.public_key()?;
            let address = host
                .addresses()
                .iter()
                .find(|address| on(address.place()))?;

            Some(WgClient {
                description: host.id().name().to_string(),
                public_key: public_key.clone(),
                allowed_ips: vec![Ipv4Network::host(address.ip())],
                route_allowed_ips: false,
                endpoint_host: None,
                endpoint_port: None,
            })
        })
        .collect()
}

fn build_mesh_interface(network: &Network, node_context: &NodeContext) -> WgInterface {
    let own_name = node_context.own_name;
    let own_node = node_context.own_node;

    info!("Generating network config for node '{own_name}'");

    let mut clients = build_node_peers(network, own_name);
    // Global clients: peers on every node.
    clients.extend(build_client_peers(network, |place| *place == Place::Mesh));
    // This node's hub clients: peers on this node only. Every other node reaches
    // them through this one, by the hub network in this node's peer entry.
    clients.extend(build_client_peers(
        network,
        |place| matches!(place, Place::Hub { node } if node == own_name),
    ));

    info!("  Mesh interface: {} peer(s)", clients.len());

    WgInterface {
        addresses: vec![own_node.mesh_address()],
        listen_port: own_node.listen_port(),
        private_key: node_context.splot_config.mesh_key().to_owned(),
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        clients,
    }
}

pub struct NetworkManager;

impl UciManager for NetworkManager {
    fn generate_commands(
        &self,
        network: &Network,
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand> {
        interface_commands(&build_mesh_interface(network, node_context))
    }

    fn config_file(&self) -> &'static str {
        FILE_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{splot_config::SplotConfig, test_support::checked, uci::UciBatchCommand};

    // Home has a hub with a client; Cabin's hub is empty.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
    hub:
      network: 10.100.84.0/24
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
";

    fn has_cmd(cmds: &[UciBatchCommand], s: &str) -> bool {
        cmds.iter().any(|c| c.to_string().contains(s))
    }

    const MESH_KEY: &str = "MESH_PRIVATE_AAAA";

    fn mesh_interface_of(network: &Network, own: &str) -> WgInterface {
        let own_name: Identifier = own.parse().unwrap();
        let splot_config = SplotConfig::for_tests(MESH_KEY);

        build_mesh_interface(
            network,
            &NodeContext {
                own_node: network.node(&own_name).unwrap(),
                own_name: &own_name,
                splot_config: &splot_config,
            },
        )
    }

    fn cmds_for(yaml: &str, own: &str) -> Vec<UciBatchCommand> {
        interface_commands(&mesh_interface_of(&checked(yaml), own))
    }

    fn cmds() -> Vec<UciBatchCommand> {
        cmds_for(FIXTURE, "Home")
    }

    #[test]
    fn the_mesh_is_the_only_interface() {
        // The reload after apply renews the mesh interface by name: it must be the
        // one interface this manager creates.
        let generated: Vec<String> = cmds()
            .iter()
            .filter_map(|command| match command {
                UciBatchCommand::Set(path, value) if value == "interface" => {
                    path.strip_prefix("network.").map(str::to_owned)
                }
                _ => None,
            })
            .collect();
        assert_eq!(generated, [naming::mesh_interface().to_string()]);
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
    fn mesh_interface_address_is_in_addresses() {
        // OpenWrt's WireGuard handler reads `addresses`; with `address` the
        // interface came up without an IP.
        let c = cmds();
        assert!(has_cmd(
            &c,
            "add_list network.spl_mesh.addresses='10.100.0.1/16'"
        ));
        assert!(!has_cmd(&c, "spl_mesh.address="));
    }

    #[test]
    fn mesh_interface_uses_mesh_private_key() {
        assert!(has_cmd(
            &cmds(),
            &format!("spl_mesh.private_key='{MESH_KEY}'")
        ));
    }

    #[test]
    fn hub_client_is_a_peer_on_its_hub_node() {
        let c = cmds();
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_camera='wireguard_spl_mesh'"
        ));
        assert!(has_cmd(
            &c,
            "add_list network.spl_wireguard_spl_mesh_camera.allowed_ips='10.100.49.10/32'"
        ));
    }

    #[test]
    fn hub_client_is_no_peer_on_other_nodes() {
        assert!(!has_cmd(
            &cmds_for(FIXTURE, "Cabin"),
            "spl_wireguard_spl_mesh_camera"
        ));
    }

    #[test]
    fn other_nodes_route_the_whole_hub_network_through_its_node() {
        assert!(has_cmd(
            &cmds_for(FIXTURE, "Cabin"),
            "add_list network.spl_wireguard_spl_mesh_Home.allowed_ips='10.100.49.0/24'"
        ));
        // Even while the hub has no clients.
        assert!(has_cmd(
            &cmds(),
            "add_list network.spl_wireguard_spl_mesh_Cabin.allowed_ips='10.100.84.0/24'"
        ));
    }

    #[test]
    fn peer_allowed_ips_never_overlap() {
        // One address, one path: WireGuard sends to the peer with the longest
        // matching prefix and doesn't check whether that peer is alive, so two
        // peers must never claim the same address.
        let example = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/splot.example.yml"));
        for yaml in [FIXTURE, example] {
            let network = checked(yaml);
            for (own, _) in network.nodes() {
                let interface = mesh_interface_of(&network, own.as_ref());
                let claims: Vec<(&str, Ipv4Network)> = interface
                    .clients
                    .iter()
                    .flat_map(|peer| {
                        peer.allowed_ips
                            .iter()
                            .map(|network| (peer.description.as_str(), *network))
                    })
                    .collect();
                assert!(!claims.is_empty(), "{own}");

                for (i, (peer, network)) in claims.iter().enumerate() {
                    for (other_peer, other) in &claims[i + 1..] {
                        assert!(
                            !network.overlap(*other),
                            "on {own}: {peer} {network} overlaps {other_peer} {other}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_global_client_is_a_peer_by_its_mesh_ip_only() {
        // Laptop has a key but no mesh IP (a warning): it's on Cabin's lan, not a
        // WireGuard peer.
        let c = cmds_for(
            "
meshNetwork: 10.100.0.0/16
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
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
clients:
  Laptop:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    macs: AA:BB:CC:DD:EE:01
    ips:
      Cabin: { lan: 192.168.2.50 }
",
            "Cabin",
        );
        assert!(has_cmd(&c, "spl_wireguard_spl_mesh_Home"), "node peer missing");
        assert!(!has_cmd(&c, "spl_wireguard_spl_mesh_Laptop"));
    }

    #[test]
    fn hyphenated_peer_names_get_valid_section_names() {
        // uci rejects '-' in section names; peers of hyphenated nodes and clients
        // use the mapped name.
        let c = cmds_for(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  old-cabin:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
clients:
  old-laptop:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.0.100
",
            "Home",
        );
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_old_cabin='wireguard_spl_mesh'"
        ));
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_old_laptop='wireguard_spl_mesh'"
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
