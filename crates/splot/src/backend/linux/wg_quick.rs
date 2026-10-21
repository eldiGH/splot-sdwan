//! The node's WireGuard as a wg-quick config file: `[Interface]` and a `[Peer]`
//! per peer, with a placeholder where each secret goes.

use std::collections::BTreeSet;

use crate::{
    backend::{
        key_store::KeyStore,
        secret::{self, MissingPsks, Secret},
    },
    plan::wireguard::{Endpoint, Peer, WireGuardPlan},
    types::{
        identifier::Identifier,
        ip::{Ipv4Interface, Ipv4Network},
    },
};

/// A line of the file: as it is, or a key whose value is a secret.
#[derive(Debug, Clone)]
enum Line {
    Text(String),
    Secret { key: &'static str, secret: Secret },
}

/// The file, and what wg-quick sets up from it besides WireGuard itself when it
/// brings the interface up: its address and its routes. `wg syncconf` changes
/// neither, so apply restarts the interface when what's live differs.
#[derive(Debug, Clone)]
pub(super) struct WgQuickConfig {
    lines: Vec<Line>,
    pub(super) address: Ipv4Interface,
    pub(super) routes: BTreeSet<Ipv4Network>,
}

impl WgQuickConfig {
    /// The file with each secret's placeholder: what the dry run shows.
    pub(super) fn masked(&self) -> String {
        self.text(self.secrets().map(Secret::placeholder))
    }

    /// The file with the secrets from `store`: what apply writes. Refuses when a
    /// pair's preshared key isn't stored.
    pub(super) fn filled(&self, store: &impl KeyStore) -> Result<String, MissingPsks> {
        Ok(self.text(secret::values(self.secrets(), store)?))
    }

    fn secrets(&self) -> impl Iterator<Item = &Secret> {
        self.lines.iter().filter_map(|line| match line {
            Line::Secret { secret, .. } => Some(secret),
            Line::Text(_) => None,
        })
    }

    /// The lines with `values` for the secrets, in order.
    fn text<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> String {
        let mut values = values.into_iter();
        let mut text = String::new();

        for line in &self.lines {
            match line {
                Line::Text(line) => text.push_str(line),
                Line::Secret { key, .. } => {
                    let value = values.next().expect("a value for every secret");
                    text.push_str(&format!("{key} = {value}"));
                }
            }
            text.push('\n');
        }

        text
    }
}

/// The routes wg-quick adds when it brings the interface up: one for each
/// peer's allowed IP that no route through the interface covers yet. The
/// interface's own network is there first, so in effect: the allowed IPs
/// outside it, the networks behind the other nodes.
fn routes(plan: &WireGuardPlan) -> BTreeSet<Ipv4Network> {
    let own = plan.address.network();

    plan.peers
        .iter()
        .flat_map(|peer| &peer.allowed_ips)
        .filter(|network| !own.contains_network(**network))
        .copied()
        .collect()
}

fn peer_lines(peer: &Peer) -> Vec<Line> {
    let text = |line: String| Line::Text(line);
    let allowed_ips: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();

    let mut lines = vec![
        // In the config's notation: `Home.camera`.
        text(format!("# {}", peer.host)),
        text("[Peer]".to_owned()),
        text(format!("PublicKey = {}", peer.public_key.as_str())),
    ];
    if peer.psk {
        lines.push(Line::Secret {
            key: "PresharedKey",
            secret: Secret::Psk(peer.host.clone()),
        });
    }
    lines.push(text(format!("AllowedIPs = {}", allowed_ips.join(", "))));
    if let Some(Endpoint { host, port }) = &peer.endpoint {
        lines.push(text(format!("Endpoint = {host}:{port}")));
    }
    if let Some(seconds) = peer.keepalive {
        lines.push(text(format!("PersistentKeepalive = {seconds}")));
    }

    lines
}

/// `node`'s WireGuard plan as its wg-quick file.
pub(super) fn render(node: &Identifier, plan: &WireGuardPlan) -> WgQuickConfig {
    let text = |line: String| Line::Text(line);

    let mut lines = vec![
        text(format!(
            "# The mesh interface of node {node}, written by splot. `splot apply`"
        )),
        text("# replaces it: change splot.yml instead.".to_owned()),
        text("[Interface]".to_owned()),
        text(format!("Address = {}", plan.address)),
        text(format!("ListenPort = {}", plan.listen_port)),
        Line::Secret {
            key: "PrivateKey",
            secret: Secret::PrivateKey,
        },
    ];
    for peer in &plan.peers {
        lines.push(text(String::new()));
        lines.extend(peer_lines(peer));
    }

    WgQuickConfig {
        lines,
        address: plan.address,
        routes: routes(plan),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::linux::key_store::FileKeyStore, model::host::HostRef, plan, test_support::checked,
    };

    // Home has a hub with a client that turns PSKs off; Cabin is reached by name
    // and has a zone; Lake can't be dialled. Phone is a global client.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: linux
      wireguard: wg-quick
      firewall: none
      dhcp: none
      dns: none
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
          psk: false
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: cabin.example.net
    listenPort: 51821
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
  Lake:
    platform:
      os: openwrt
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    listenPort: 51820
    meshIp: 10.100.0.3
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.1.10
";

    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSA=";
    const LAKE_PSK: &str = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTA=";
    const PHONE_PSK: &str = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUA=";

    fn config_for(yaml: &str, node: &str) -> WgQuickConfig {
        let plan = plan::plan(&checked(yaml), &node.parse().unwrap()).unwrap();
        render(&plan.node, plan.wireguard.as_ref().unwrap())
    }

    fn store(psks: &[(&str, &str)]) -> FileKeyStore {
        psks.iter().fold(
            FileKeyStore::for_tests(PRIVATE_KEY),
            |store, (peer, key)| store.with_psk(&HostRef::Node(peer.parse().unwrap()), key),
        )
    }

    #[test]
    fn the_file_has_the_interface_then_a_section_per_peer() {
        assert_eq!(
            config_for(FIXTURE, "Home").masked(),
            "\
# The mesh interface of node Home, written by splot. `splot apply`
# replaces it: change splot.yml instead.
[Interface]
Address = 10.100.0.1/16
ListenPort = 51820
PrivateKey = <private key>

# Cabin
[Peer]
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
PresharedKey = <preshared key>
AllowedIPs = 10.100.0.2/32, 192.168.2.0/24
Endpoint = cabin.example.net:51821

# Lake
[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
PresharedKey = <preshared key>
AllowedIPs = 10.100.0.3/32

# Phone
[Peer]
PublicKey = EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
PresharedKey = <preshared key>
AllowedIPs = 10.100.1.10/32

# Home.camera
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
AllowedIPs = 10.100.49.10/32
"
        );
    }

    #[test]
    fn a_node_nobody_can_dial_keeps_alive_toward_the_peers_it_dials() {
        let lake = config_for(FIXTURE, "Lake").masked();
        let section = |peer: &str| {
            let start = lake.find(&format!("# {peer}\n")).unwrap();
            lake[start..].split("\n\n").next().unwrap().to_owned()
        };

        assert!(section("Home").contains("\nPersistentKeepalive = 25"));
        assert!(section("Cabin").contains("\nPersistentKeepalive = 25"));
        assert!(!section("Phone").contains("PersistentKeepalive"));
        // Home, which others can dial, sends none.
        assert!(
            !config_for(FIXTURE, "Home")
                .masked()
                .contains("PersistentKeepalive")
        );
    }

    #[test]
    fn apply_fills_in_the_secrets_and_the_rendered_file_holds_none() {
        let config = config_for(FIXTURE, "Home");
        let filled = config
            .filled(
                &store(&[("Cabin", CABIN_PSK), ("Lake", LAKE_PSK)])
                    .with_psk(&HostRef::Client("Phone".parse().unwrap()), PHONE_PSK),
            )
            .unwrap();

        assert!(filled.contains(&format!("\nPrivateKey = {PRIVATE_KEY}\n")));
        for psk in [CABIN_PSK, LAKE_PSK, PHONE_PSK] {
            assert_eq!(filled.matches(psk).count(), 1, "{psk}");
        }
        // Each in its peer's section.
        assert!(filled.contains(&format!(
            "# Lake\n[Peer]\nPublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=\nPresharedKey = {LAKE_PSK}\n"
        )));
        // Nothing else moved: the filled file is the masked one with the secrets in.
        let masked = config.masked();
        assert_eq!(filled.lines().count(), masked.lines().count());
        assert!(!filled.contains('<'));

        for secret in [PRIVATE_KEY, CABIN_PSK, LAKE_PSK, PHONE_PSK] {
            assert!(!masked.contains(secret));
        }
    }

    #[test]
    fn apply_refuses_while_a_pairs_psk_is_missing() {
        let MissingPsks(missing) = config_for(FIXTURE, "Home")
            .filled(&store(&[("Lake", LAKE_PSK)]))
            .unwrap_err();
        assert_eq!(missing, ["Cabin", "Phone"]);
    }

    #[test]
    fn wg_quick_routes_the_networks_behind_the_other_nodes() {
        // The mesh's own addresses (mesh IPs, hubs, global clients) are on the
        // interface's network already.
        let routes = |node: &str| -> Vec<String> {
            config_for(FIXTURE, node)
                .routes
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(routes("Home"), ["192.168.2.0/24"]);
        assert!(routes("Cabin").is_empty());
    }

    #[test]
    fn wg_quick_routes_what_the_plan_routes_and_nothing_else() {
        // wg-quick routes every allowed IP outside the interface's network; the
        // plan routes a node's networks, not a client's own IP. They agree only
        // because a client's IP is always inside the mesh: checked here for every
        // node of the example, so a change to either shows up.
        let example = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../splot.example.yml"
        ));
        let network = checked(example);
        let mut routes_seen = 0;

        for node in network.nodes() {
            let plan = plan::plan(&network, node.name())
                .unwrap()
                .wireguard
                .unwrap();
            let mesh = plan.address.network();
            let outside = |peer: &&Peer| -> Vec<Ipv4Network> {
                peer.allowed_ips
                    .iter()
                    .filter(|ip| !mesh.contains_network(**ip))
                    .copied()
                    .collect()
            };

            let routed: BTreeSet<Ipv4Network> = plan
                .peers
                .iter()
                .filter(|peer| peer.routed)
                .flat_map(|peer| outside(&peer))
                .collect();
            assert_eq!(routes(&plan), routed, "{}", node.name());
            routes_seen += routed.len();

            for peer in plan.peers.iter().filter(|peer| !peer.routed) {
                assert!(outside(&peer).is_empty(), "{}: {}", node.name(), peer.host);
            }
        }
        assert!(routes_seen > 0);
    }
}
