use log::{debug, info};

use super::{
    naming::{self, UciSectionName},
    secret::{Secret, Slot},
    section::{Section, UciSection, UciSectionBuilder},
};
use crate::{
    consts,
    plan::{
        NodePlan,
        wireguard::{Endpoint, Peer, WireGuardPlan},
    },
};

pub(super) const FILE: &str = "network";

/// The interface's option that holds the node's private key. The plan has no
/// key, so neither has what's rendered from it: a placeholder, which `apply`
/// fills in from the key store.
const PRIVATE_KEY: &str = "private_key";
/// A peer's option that holds its pair's preshared key: a placeholder too.
const PRESHARED_KEY: &str = "preshared_key";

/// The mesh interface.
struct MeshInterface<'a> {
    plan: &'a WireGuardPlan,
}

impl UciSection for MeshInterface<'_> {
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
            .set(PRIVATE_KEY, Secret::PrivateKey.placeholder())
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
    fn section_type(&self) -> &str {
        self.section_type
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.peer.host.name().as_ref()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let peer = self.peer;

        section
            // In the config's notation: `[SPLOT] Home.camera`.
            .set("description", naming::name_prefixed(&peer.host.to_string()))
            .set("public_key", peer.public_key.as_str())
            .set_if_some(PRESHARED_KEY, peer.psk.then(|| psk(peer).placeholder()))
            .set("route_allowed_ips", if peer.routed { "1" } else { "0" })
            .set_if_some(
                "persistent_keepalive",
                peer.keepalive.map(|seconds| seconds.to_string()),
            )
            .set_if_some(
                "endpoint_host",
                peer.endpoint
                    .as_ref()
                    .map(|Endpoint { host, .. }| host.to_string()),
            )
            .set_if_some(
                "endpoint_port",
                peer.endpoint
                    .as_ref()
                    .map(|Endpoint { port, .. }| port.to_string()),
            )
            .extend_list("allowed_ips", &peer.allowed_ips)
    }
}

/// The secret in a peer section whose pair uses a preshared key.
fn psk(peer: &Peer) -> Secret {
    Secret::Psk(peer.host.clone())
}

/// The mesh interface's section, followed by one section per peer, and where
/// their secrets go: the interface's private key, and the preshared key of each
/// pair that uses one.
fn interface_sections(plan: &WireGuardPlan) -> (Vec<Section>, Vec<Slot>) {
    let interface = MeshInterface { plan };
    let peer_type = format!("wireguard_{}", interface.section_name());

    let mut sections = vec![interface.to_section()];
    let mut secrets = vec![Slot {
        file: FILE,
        section: interface.section_name().to_string(),
        option: PRIVATE_KEY,
        secret: Secret::PrivateKey,
    }];

    for peer in &plan.peers {
        let section = PeerSection {
            section_type: &peer_type,
            peer,
        };
        if peer.psk {
            secrets.push(Slot {
                file: FILE,
                section: section.section_name().to_string(),
                option: PRESHARED_KEY,
                secret: psk(peer),
            });
        }
        sections.push(section.to_section());
    }

    (sections, secrets)
}

/// The plan's WireGuard section as the `network` file's sections, with a
/// placeholder for each secret, and where they are.
pub(super) fn render(plan: &NodePlan) -> (Vec<Section>, Vec<Slot>) {
    info!("Generating network config for node '{}'", plan.node);
    for peer in &plan.wireguard.peers {
        debug!(
            "  Mesh peer '{}': {} AllowedIPs",
            peer.host,
            peer.allowed_ips.len()
        );
    }
    info!("  Mesh interface: {} peer(s)", plan.wireguard.peers.len());

    interface_sections(&plan.wireguard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backend::openwrt::uci::UciBatchCommand, plan, test_support::checked};

    // Home has a hub with a client; Cabin's hub is empty.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
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
    platform:
      os: openwrt
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

    fn cmds_for(yaml: &str, own: &str) -> Vec<UciBatchCommand> {
        let plan = plan::plan(&checked(yaml), &own.parse().unwrap()).unwrap();
        interface_sections(&plan.wireguard)
            .0
            .iter()
            .flat_map(|section| section.commands("network"))
            .collect()
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
    fn a_peer_endpoint_is_its_address_or_its_name() {
        assert!(has_cmd(&cmds(), "spl_mesh_Cabin.endpoint_host='5.6.7.8'"));

        let yaml = FIXTURE.replace("endpoint: 5.6.7.8", "endpoint: cabin.example.net");
        let c = cmds_for(&yaml, "Home");
        assert!(has_cmd(
            &c,
            "spl_mesh_Cabin.endpoint_host='cabin.example.net'"
        ));
        assert!(has_cmd(&c, "spl_mesh_Cabin.endpoint_port='51820'"));
    }

    #[test]
    fn a_node_nobody_can_dial_has_no_endpoint_and_sends_keepalives() {
        let yaml = FIXTURE.replace(
            "\nclients:",
            "
  Lake:
    platform:
      os: openwrt
    publicKey: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA=
    listenPort: 51820
    meshIp: 10.100.0.3
clients:",
        );

        let c = cmds_for(&yaml, "Home");
        assert!(has_cmd(&c, "network.spl_wireguard_spl_mesh_Lake="));
        assert!(!has_cmd(&c, "spl_mesh_Lake.endpoint"));
        assert!(!has_cmd(&c, "persistent_keepalive"));

        let c = cmds_for(&yaml, "Lake");
        assert!(has_cmd(&c, "spl_mesh_Home.persistent_keepalive='25'"));
        assert!(!has_cmd(&c, "spl_mesh_Phone.persistent_keepalive"));
        assert!(has_cmd(&c, "spl_mesh_Home.endpoint_host='1.2.3.4'"));
    }

    #[test]
    fn a_pair_with_a_psk_gets_a_placeholder_and_a_slot() {
        let yaml = FIXTURE.replace(
            "          ip: 10.100.49.10\n",
            "          ip: 10.100.49.10\n          psk: false\n",
        );
        let plan = plan::plan(&checked(&yaml), &"Home".parse().unwrap()).unwrap();
        let (sections, secrets) = interface_sections(&plan.wireguard);

        let c: Vec<_> = sections
            .iter()
            .flat_map(|section| section.commands("network"))
            .collect();
        assert!(has_cmd(
            &c,
            "spl_mesh_Cabin.preshared_key='<preshared key>'"
        ));
        assert!(has_cmd(
            &c,
            "spl_mesh_Phone.preshared_key='<preshared key>'"
        ));
        // The camera turned it off.
        assert!(!has_cmd(&c, "spl_mesh_camera.preshared_key"));

        let slots: Vec<String> = secrets
            .iter()
            .map(|slot| {
                format!(
                    "{}.{}.{}: {:?}",
                    slot.file, slot.section, slot.option, slot.secret
                )
            })
            .collect();
        assert_eq!(
            slots,
            [
                "network.spl_mesh.private_key: PrivateKey",
                "network.spl_wireguard_spl_mesh_Cabin.preshared_key: Psk(Node(Identifier(\"Cabin\")))",
                "network.spl_wireguard_spl_mesh_Phone.preshared_key: Psk(Client(Identifier(\"Phone\")))",
            ]
        );
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
    fn the_private_key_is_a_placeholder_apply_fills_in() {
        // The plan holds no private key, so neither does what's rendered from it:
        // not the snapshot, not the dry run.
        assert!(has_cmd(
            &cmds(),
            "set network.spl_mesh.private_key='<private key>'"
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
    fn a_peer_is_described_in_config_notation() {
        let c = cmds();
        // A hub client by its qualified name; the section keeps its local one.
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_camera.description='[SPLOT] Home.camera'"
        ));
        assert!(has_cmd(
            &c,
            "set network.spl_wireguard_spl_mesh_Cabin.description='[SPLOT] Cabin'"
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
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  old-cabin:
    platform:
      os: openwrt
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
