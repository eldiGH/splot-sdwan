use log::{debug, info};

use super::{
    naming::{self, UciSectionName},
    section::{UciSection, UciSectionBuilder},
    uci::UciBatchCommand,
};
use crate::{
    consts,
    plan::{
        NodePlan,
        wireguard::{Endpoint, Peer, WireGuardPlan},
    },
};

pub(super) const FILE: &str = "network";

/// The mesh interface: the plan's interface, with the node's private key.
struct MeshInterface<'a> {
    plan: &'a WireGuardPlan,
    private_key: &'a str,
}

impl UciSection for MeshInterface<'_> {
    const FILE: &'static str = FILE;

    fn section_type(&self) -> &str {
        "interface"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [consts::MESH_INTERFACE_NAME]
    }

    /// Not `spl_interface_<name>`: an interface's section name is the interface
    /// name itself. Zones and peer section types refer to it, and netifd names the
    /// WireGuard device after it (at most 15 characters).
    fn section_name(&self) -> UciSectionName {
        naming::mesh_interface()
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("proto", "wireguard")
            .set("private_key", self.private_key)
            .set("listen_port", self.plan.listen_port.to_string())
            // Not `address`: OpenWrt's WireGuard handler reads `addresses`.
            .extend_list("addresses", [self.plan.address])
    }
}

/// A peer as a uci section. Its section type names the interface it belongs to
/// (`wireguard_<interface>`), which the peer itself doesn't know.
struct PeerSection<'a> {
    section_type: &'a str,
    peer: &'a Peer,
}

impl UciSection for PeerSection<'_> {
    const FILE: &'static str = FILE;

    fn section_type(&self) -> &str {
        self.section_type
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.peer.host.name().as_ref()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let peer = self.peer;

        section
            .set(
                "description",
                naming::name_prefixed(peer.host.name().as_ref()),
            )
            .set("public_key", peer.public_key.as_str())
            .set("route_allowed_ips", if peer.routed { "1" } else { "0" })
            .set_if_some(
                "persistent_keepalive",
                peer.keepalive.map(|seconds| seconds.to_string()),
            )
            .set_if_some(
                "endpoint_host",
                peer.endpoint.map(|Endpoint { host, .. }| host.to_string()),
            )
            .set_if_some(
                "endpoint_port",
                peer.endpoint.map(|Endpoint { port, .. }| port.to_string()),
            )
            .extend_list("allowed_ips", &peer.allowed_ips)
    }
}

/// The mesh interface's section, followed by one section per peer.
fn interface_commands(plan: &WireGuardPlan, private_key: &str) -> Vec<UciBatchCommand> {
    let interface = MeshInterface { plan, private_key };
    let peer_type = format!("wireguard_{}", interface.section_name());

    let mut commands = interface.to_uci_commands();
    for peer in &plan.peers {
        let section = PeerSection {
            section_type: &peer_type,
            peer,
        };
        commands.extend(section.to_uci_commands());
    }

    commands
}

/// The plan's WireGuard section as the `network` file's commands, with the node's
/// private key.
pub(super) fn render(plan: &NodePlan, private_key: &str) -> Vec<UciBatchCommand> {
    info!("Generating network config for node '{}'", plan.node);
    for peer in &plan.wireguard.peers {
        debug!(
            "  Mesh peer '{}': {} AllowedIPs",
            peer.host,
            peer.allowed_ips.len()
        );
    }
    info!("  Mesh interface: {} peer(s)", plan.wireguard.peers.len());

    interface_commands(&plan.wireguard, private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support::checked};

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

    fn cmds_for(yaml: &str, own: &str) -> Vec<UciBatchCommand> {
        let plan = plan::plan(&checked(yaml), &own.parse().unwrap()).unwrap();
        interface_commands(&plan.wireguard, MESH_KEY)
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
