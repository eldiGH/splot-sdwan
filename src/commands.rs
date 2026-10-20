//! What each command does, once the config is loaded and checked.

use std::net::Ipv4Addr;

use anyhow::{Context, bail};

use crate::{
    backend::{
        Backend,
        openwrt::OpenWrtBackend,
        openwrt::splot_config::{SplotConfig, SplotConfigError},
    },
    model::Network,
    plan::{self, NodePlan},
    types::{
        identifier::Identifier,
        platform::Os,
        wg_key::{WgPresharedKey, WgPublicKey},
    },
    wg,
};

/// The listen port suggested to a new node: WireGuard's usual one.
const SUGGESTED_LISTEN_PORT: u16 = 51820;

/// `init`: gives this peer its WireGuard key, unless it has one (a key is
/// never replaced), and says what the config needs for `node`: nothing, its new
/// key, or a whole entry to paste.
pub fn init(network: &Network, node: &Identifier) -> anyhow::Result<()> {
    if let Some(known) = network.node(node)
        && known.platform().os() != Os::OpenWrt
    {
        bail!(
            "{node} runs {}: `splot init` keeps the key with uci, on OpenWrt only for now",
            known.platform().os()
        );
    }

    let (store, created) = match SplotConfig::load() {
        Ok(store) => (store, false),
        Err(SplotConfigError::NotInitialised) => {
            SplotConfig::create_private_key()?;
            (SplotConfig::load()?, true)
        }
        Err(err) => return Err(err.into()),
    };
    let public_key =
        wg::get_pubkey(store.mesh_key()).context("failed to derive this peer's public key")?;

    if created {
        println!("Generated this peer's WireGuard key.");
    }

    match enrolment(network, node, &public_key) {
        Enrolment::Initialised => {
            println!("{node} is already initialised: the config has this peer's key for it.");
        }
        Enrolment::SomeoneElses(at) => {
            bail!("this peer's key is the one at {at}, so this peer isn't {node}: check `--node`")
        }
        // A key just made can't be in the config yet: that's the next step.
        Enrolment::OtherKey if created => println!(
            "The config has another key for {node}. If this peer is {node} (new, reinstalled, or its key rotated), set nodes.{node}.publicKey to:\n  {public_key}"
        ),
        Enrolment::OtherKey => bail!(
            "this peer's key isn't in the config, neither as {node}'s nor as anyone else's. If this peer is {node} (reinstalled, or its key rotated), set nodes.{node}.publicKey to:\n  {public_key}"
        ),
        Enrolment::NewNode => print!(
            "{node} isn't in the config yet; add it under `nodes:`:\n\n{}",
            new_node_entry(node, &public_key, network.free_mesh_ip())
        ),
    }

    Ok(())
}

/// What the config says about this peer's key, for the node `init` was given.
#[derive(Debug, PartialEq, Eq)]
enum Enrolment {
    /// The config has this key for the node.
    Initialised,
    /// The key is another entry's, there.
    SomeoneElses(String),
    /// The config has another key for the node, and this one nowhere.
    OtherKey,
    /// Neither the node nor the key is in the config.
    NewNode,
}

fn enrolment(network: &Network, node: &Identifier, key: &WgPublicKey) -> Enrolment {
    match (network.node(node), network.key_location(key)) {
        (Some(known), _) if known.public_key() == key => Enrolment::Initialised,
        (_, Some(at)) => Enrolment::SomeoneElses(at.to_string()),
        (Some(_), None) => Enrolment::OtherKey,
        (None, None) => Enrolment::NewNode,
    }
}

/// A new node's entry for the config, to paste under `nodes:`.
fn new_node_entry(
    node: &Identifier,
    public_key: &WgPublicKey,
    mesh_ip: Option<Ipv4Addr>,
) -> String {
    let mesh_ip = match mesh_ip {
        Some(ip) => format!("{ip}  # the lowest free address in meshNetwork; once set, keep it"),
        None => "<an address in meshNetwork>  # it has no free address left".to_owned(),
    };

    // `init` runs on OpenWrt only, for now: it keeps the key with uci.
    format!(
        "  {node}:
    platform:
      os: openwrt
    publicKey: {public_key}
    meshIp: {mesh_ip}
    listenPort: {SUGGESTED_LISTEN_PORT}
    # endpoint: where the other nodes dial it, its public IP or DNS name;
    # leave it out if nobody can (behind NAT)
"
    )
}

/// `apply`: makes this peer's config what the plan for `node` says, or shows
/// what that would change (`dry_run`). The backend first checks this peer is
/// `node`.
pub fn apply(network: &Network, node: &Identifier, dry_run: bool) -> anyhow::Result<()> {
    let plan = node_plan(network, node)?;
    check_applicable(network, node)?;
    let splot_config = SplotConfig::load()?;

    let backend = OpenWrtBackend::new(splot_config);
    let rendered = backend.render(&plan);

    if dry_run {
        backend.dry_run(&rendered)?;
    } else {
        let changed = backend.apply(&rendered)?;

        if changed.is_empty() {
            println!("Nothing changed.");
        } else {
            println!("Applied and reloaded: {}", changed.join(", "));
        }
    }

    Ok(())
}

/// `psk set`: stores the preshared key of the pair of `node` (this peer) with
/// `peer`, read from stdin, once it's checked this peer is `node`.
pub fn psk_set(network: &Network, node: &Identifier, peer: &str) -> anyhow::Result<()> {
    let plan = node_plan(network, node)?;
    check_applicable(network, node)?;
    let splot_config = SplotConfig::load()?;
    splot_config.check_node(&plan.node, &plan.public_key)?;

    let Some(wireguard) = &plan.wireguard else {
        bail!(
            "splot leaves {}'s WireGuard alone (wireguard: none): it sets up no peers there, so it keeps no preshared keys",
            plan.node
        );
    };
    let Some(peer) = wireguard.peer(peer) else {
        let peers: Vec<String> = wireguard
            .peers
            .iter()
            .map(|peer| peer.host.to_string())
            .collect();
        bail!(
            "'{peer}' isn't a peer of {}; its peers are {}",
            plan.node,
            peers.join(", ")
        );
    };
    if !peer.psk {
        bail!(
            "{}'s pair with {} uses no preshared key: one of them sets `psk: false`",
            plan.node,
            peer.host
        );
    }

    let mut key = String::new();
    std::io::stdin()
        .read_line(&mut key)
        .context("failed to read the preshared key from stdin")?;
    let key: WgPresharedKey = key
        .trim()
        .parse()
        .context("that's not a preshared key (as `wg genpsk` prints one)")?;
    SplotConfig::store_psk(&peer.host, &key)?;

    println!(
        "Stored the preshared key of {}'s pair with {}.",
        plan.node, peer.host
    );

    Ok(())
}

/// Refuses a node splot can only check for now, not apply to: one that doesn't
/// run OpenWrt, or leaves its WireGuard alone (`none`): the key check needs
/// splot's own key there.
fn check_applicable(network: &Network, node: &Identifier) -> anyhow::Result<()> {
    let Some(node) = network.node(node) else {
        return Ok(());
    };
    let platform = node.platform();

    if platform.os() != Os::OpenWrt {
        bail!(
            "{} runs {}: splot can check it, but can't apply to it yet",
            node.name(),
            platform.os()
        );
    }

    if platform.wireguard().is_none() {
        bail!(
            "splot leaves {}'s WireGuard alone (wireguard: none): it can check the node, but can't apply to it yet",
            node.name()
        );
    }

    Ok(())
}

/// The plan for `node`; an error naming the config's nodes when it has no node
/// of that name.
fn node_plan(network: &Network, node: &Identifier) -> anyhow::Result<NodePlan> {
    plan::plan(network, node).with_context(|| {
        let nodes: Vec<String> = network
            .nodes()
            .map(|node| node.name().to_string())
            .collect();
        format!(
            "there's no node {node} in the config; its nodes are {}",
            nodes.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    #[test]
    fn a_new_node_entry_pasted_into_the_config_is_that_node() {
        let config = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
";
        let key: WgPublicKey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
            .parse()
            .unwrap();
        let cabin: Identifier = "Cabin".parse().unwrap();
        let ip = checked(config).free_mesh_ip();

        let network = checked(&format!("{config}{}", new_node_entry(&cabin, &key, ip)));
        let node = network.node(&cabin).unwrap();

        assert_eq!(*node.public_key(), key);
        assert_eq!(node.mesh_address().to_string(), "10.100.0.2/16");
        assert_eq!(node.listen_port().to_string(), "51820");
        // Behind NAT until someone writes an endpoint in.
        assert!(node.endpoint().is_none());
    }

    #[test]
    fn init_finds_whose_key_this_peer_has() {
        // Home's key is A, Cabin's C, the camera on Home's hub B, Phone's D.
        let network = checked(
            "
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
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
",
        );
        let enrolment = |node: &str, key: char| {
            let key: WgPublicKey = format!("{}A=", key.to_string().repeat(42)).parse().unwrap();
            enrolment(&network, &node.parse().unwrap(), &key)
        };
        let theirs = |at: &str| Enrolment::SomeoneElses(at.to_owned());

        assert_eq!(enrolment("Home", 'A'), Enrolment::Initialised);
        // Someone else's key, whether the node is in the config or not.
        assert_eq!(enrolment("Home", 'C'), theirs("nodes.Cabin.publicKey"));
        assert_eq!(
            enrolment("Home", 'B'),
            theirs("nodes.Home.hub.clients.camera.publicKey")
        );
        assert_eq!(enrolment("Pond", 'D'), theirs("clients.Phone.publicKey"));
        // A key the config doesn't know.
        assert_eq!(enrolment("Home", 'Z'), Enrolment::OtherKey);
        assert_eq!(enrolment("Pond", 'Z'), Enrolment::NewNode);
    }

    #[test]
    fn splot_applies_to_openwrt_nodes_whose_wireguard_it_manages() {
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
      dns: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    platform:
      os: openwrt
      firewall: none
      dhcp: none
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
  Lake:
    platform:
      os: openwrt
      wireguard: none
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    listenPort: 51820
    meshIp: 10.100.0.3
  Pond:
    platform:
      os: linux
      wireguard: wg-quick
      firewall: nftables
      dhcp: dnsmasq
      dns: dnsmasq
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    endpoint: 9.10.11.12
    listenPort: 51820
    meshIp: 10.100.0.4
",
        );
        let applicable = |node: &str| {
            check_applicable(&network, &node.parse().unwrap()).map_err(|err| err.to_string())
        };

        assert!(applicable("Home").is_ok());
        assert!(applicable("Cabin").is_ok());
        assert_eq!(
            applicable("Lake").unwrap_err(),
            "splot leaves Lake's WireGuard alone (wireguard: none): it can check the node, but can't apply to it yet"
        );
        assert_eq!(
            applicable("Pond").unwrap_err(),
            "Pond runs linux: splot can check it, but can't apply to it yet"
        );
    }

    #[test]
    fn a_node_the_config_doesnt_have_is_named_with_the_ones_it_has() {
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );

        let err = node_plan(&network, &"Pond".parse().unwrap()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "there's no node Pond in the config; its nodes are Cabin, Home"
        );
        assert_eq!(
            node_plan(&network, &"Home".parse().unwrap())
                .unwrap()
                .node
                .as_ref(),
            "Home"
        );
    }
}
