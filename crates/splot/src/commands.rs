//! What each command does, once the config is loaded and checked.

use std::net::Ipv4Addr;

use anyhow::{Context, bail};

use splot_core::protocol::{Probe, Reply, Request};

use crate::{
    agent::{self, Agent},
    model::{Network, host::HostRef},
    plan::{self, NodePlan},
    types::{
        identifier::Identifier,
        platform::{
            self, Concern, DhcpProgram, DnsProgram, FirewallProgram, Os, Program, WireGuardProgram,
        },
        wg_key::{WgPresharedKey, WgPublicKey},
    },
};

/// The listen port suggested to a new node: WireGuard's usual one.
const SUGGESTED_LISTEN_PORT: u16 = 51820;

/// The OS this peer runs, which decides where its keys are kept: what the
/// config says for `node`, else what `--os` says, else what this peer looks like
/// (`detected`). Any two that disagree is an error: the config or `--os` would
/// be wrong about this peer.
fn peer_os(
    node: &Identifier,
    config: Option<Os>,
    flag: Option<Os>,
    detected: Option<Os>,
) -> anyhow::Result<Os> {
    if let (Some(config), Some(flag)) = (config, flag)
        && config != flag
    {
        bail!("--os says {flag}, but the config says {node} runs {config}");
    }

    let Some(os) = config.or(flag).or(detected) else {
        let names: Vec<String> = Os::ALL.iter().map(|os| format!("--os {os}")).collect();
        bail!(
            "can't tell which OS this peer runs, and the config doesn't have {node} yet: say it with {}",
            names.join(" or ")
        );
    };

    match detected {
        Some(detected) if detected != os && config.is_some() => {
            bail!("this peer runs {detected}, but the config says {node} runs {os}")
        }
        Some(detected) if detected != os => bail!("this peer runs {detected}, but --os says {os}"),
        _ => Ok(os),
    }
}

/// `init`: gives this peer its WireGuard key, unless it has one (a key is
/// never replaced), and says what the config needs for `node`: nothing, its new
/// key, or a whole entry to paste. The key goes in the key store of the OS the
/// peer runs (see `peer_os`). A node whose WireGuard splot leaves alone needs
/// no key of splot's.
pub fn init(
    network: &Network,
    node: &Identifier,
    os: Option<Os>,
    agent: &mut Agent,
) -> anyhow::Result<()> {
    let known = network.node(node);
    let detected = match agent.ask(Request::Os)? {
        Reply::Os(detected) => detected,
        reply => return Err(agent::unexpected(reply)),
    };
    let os = peer_os(node, known.map(|known| known.platform().os()), os, detected)?;

    if known.is_some_and(|known| known.platform().wireguard().is_none()) {
        println!(
            "splot leaves {node}'s WireGuard alone (wireguard: none), so it keeps no key there: nothing to initialise. apply checks this peer is {node} by its own WireGuard's key."
        );
        return Ok(());
    }

    let (public_key, created) = match agent.ask(Request::Init { os })? {
        Reply::Initialised {
            public_key,
            created,
        } => (public_key, created),
        reply => return Err(agent::unexpected(reply)),
    };

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
            new_node_entry(node, os, &public_key, network.free_mesh_ip())
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

/// The programs splot can manage `P`'s concern with on `os`.
fn programs_on<P: Program>(os: Os) -> String {
    platform::names(P::ALL.iter().copied().filter(|program| program.runs_on(os)))
}

/// A new node's `platform`, for a peer that runs `os`. OpenWrt's defaults are
/// what it ships. Linux has none, so every concern is written out: the
/// WireGuard splot just made the key for, and the rest left to the operator
/// until they choose otherwise.
fn new_node_platform(os: Os) -> String {
    match os {
        Os::OpenWrt => format!("      os: {os}\n"),
        Os::Linux => format!(
            "      os: {os}
      wireguard: {}
      # What else splot manages on it; `none` leaves it to you.
      firewall: none  # or {}
      dhcp: none  # or {}
      dns: none  # or {}
",
            WireGuardProgram::WgQuick,
            programs_on::<FirewallProgram>(os),
            programs_on::<DhcpProgram>(os),
            programs_on::<DnsProgram>(os),
        ),
    }
}

/// A new node's entry for the config, to paste under `nodes:`.
fn new_node_entry(
    node: &Identifier,
    os: Os,
    public_key: &WgPublicKey,
    mesh_ip: Option<Ipv4Addr>,
) -> String {
    let mesh_ip = match mesh_ip {
        Some(ip) => format!("{ip}  # the lowest free address in meshNetwork; once set, keep it"),
        None => "<an address in meshNetwork>  # it has no free address left".to_owned(),
    };

    format!(
        "  {node}:
    platform:
{}    publicKey: {public_key}
    meshIp: {mesh_ip}
    listenPort: {SUGGESTED_LISTEN_PORT}
    # endpoint: where the other nodes dial it, its public IP or DNS name;
    # leave it out if nobody can (behind NAT). With one, and its firewall
    # splot's, wanZone: the firewall zone its listen port is let in from
",
        new_node_platform(os)
    )
}

/// What a node checks after a change: its node peers, each pinged at its mesh
/// IP. The ones that answer before the change must answer after it.
pub(crate) fn probes(plan: &NodePlan) -> Vec<Probe> {
    plan.wireguard
        .iter()
        .flat_map(|wireguard| &wireguard.peers)
        .filter(|peer| matches!(peer.host, HostRef::Node(_)))
        .map(|peer| Probe {
            peer: peer.host.to_string(),
            address: peer.address,
        })
        .collect()
}

/// The OS the config says `node` runs: for a node it has a plan for.
pub(crate) fn node_os(network: &Network, node: &Identifier) -> Os {
    network
        .node(node)
        .expect("a node the config has a plan for is in the config")
        .platform()
        .os()
}

/// `psk set`: stores the preshared key of the pair of `node` (this peer) with
/// `peer`, read from stdin. The agent checks this peer is `node` before it
/// stores it.
pub fn psk_set(
    network: &Network,
    node: &Identifier,
    peer: &str,
    agent: &mut Agent,
) -> anyhow::Result<()> {
    let plan = node_plan(network, node)?;
    let os = node_os(network, node);
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

    match agent.ask(Request::StorePsk {
        node: plan.node.clone(),
        public_key: plan.public_key.clone(),
        os,
        peer: peer.host.clone(),
        key,
    })? {
        Reply::Stored => {}
        reply => return Err(agent::unexpected(reply)),
    }

    println!(
        "Stored the preshared key of {}'s pair with {}.",
        plan.node, peer.host
    );

    Ok(())
}

/// Refuses a node that asks splot for what it can check but not do yet: on
/// Linux, its firewall and DHCP. Applying the rest alone would leave the node
/// short of what the config says.
pub(crate) fn check_applicable(network: &Network, node: &Identifier) -> anyhow::Result<()> {
    let Some(node) = network.node(node) else {
        return Ok(());
    };
    let platform = node.platform();
    if platform.os() != Os::Linux {
        return Ok(());
    }

    let not_yet: Vec<String> = [
        platform
            .firewall()
            .map(|program| format!("{} ({program})", Concern::Firewall)),
        platform
            .dhcp()
            .map(|program| format!("{} ({program})", Concern::Dhcp)),
    ]
    .into_iter()
    .flatten()
    .collect();

    match not_yet.as_slice() {
        [] => Ok(()),
        [one] => bail!(
            "splot can't manage {}'s {one} on Linux yet: set it to `none` to apply the rest",
            node.name()
        ),
        several => bail!(
            "splot can't manage {}'s {} on Linux yet: set them to `none` to apply the rest",
            node.name(),
            several.join(" or ")
        ),
    }
}

/// The plan for `node`; an error naming the config's nodes when it has no node
/// of that name.
pub(crate) fn node_plan(network: &Network, node: &Identifier) -> anyhow::Result<NodePlan> {
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
    fn the_peers_os_is_the_configs_else_os_else_detected() {
        let os = |config, flag, detected| {
            peer_os(&"Barn".parse().unwrap(), config, flag, detected).map_err(|err| err.to_string())
        };
        let (openwrt, linux) = (Some(Os::OpenWrt), Some(Os::Linux));

        // Each alone, or agreeing with the others.
        for one in [openwrt, linux] {
            assert_eq!(os(one, None, None), Ok(one.unwrap()));
            assert_eq!(os(None, one, None), Ok(one.unwrap()));
            assert_eq!(os(None, None, one), Ok(one.unwrap()));
            assert_eq!(os(one, one, one), Ok(one.unwrap()));
        }

        // Any two that disagree, either way round.
        for (one, other) in [(openwrt, linux), (linux, openwrt)] {
            let (one_name, other_name) = (one.unwrap(), other.unwrap());
            assert_eq!(
                os(one, other, None),
                Err(format!(
                    "--os says {other_name}, but the config says Barn runs {one_name}"
                ))
            );
            assert_eq!(
                os(one, None, other),
                Err(format!(
                    "this peer runs {other_name}, but the config says Barn runs {one_name}"
                ))
            );
            assert_eq!(
                os(None, one, other),
                Err(format!(
                    "this peer runs {other_name}, but --os says {one_name}"
                ))
            );
        }

        assert_eq!(
            os(None, None, None),
            Err("can't tell which OS this peer runs, and the config doesn't have Barn yet: say it with --os openwrt or --os linux".to_owned())
        );
    }

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
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
";
        let key: WgPublicKey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
            .parse()
            .unwrap();
        let cabin: Identifier = "Cabin".parse().unwrap();
        let ip = checked(config).free_mesh_ip();

        for os in Os::ALL {
            let entry = new_node_entry(&cabin, os, &key, ip);
            let network = checked(&format!("{config}{entry}"));
            let node = network.node(&cabin).unwrap();

            assert_eq!(*node.public_key(), key);
            assert_eq!(node.mesh_address().to_string(), "10.100.0.2/16");
            assert_eq!(node.listen_port().to_string(), "51820");
            // Behind NAT until someone writes an endpoint in.
            assert!(node.endpoint().is_none());

            // The OS it was made on. splot runs its WireGuard (that's what the
            // key is for), and on Linux, which has no defaults, leaves the rest
            // alone until the operator says otherwise.
            let platform = node.platform();
            assert_eq!(platform.os(), os, "{entry}");
            assert!(platform.wireguard().is_some(), "{entry}");
            if os == Os::Linux {
                assert_eq!(platform.wireguard(), Some(WireGuardProgram::WgQuick));
                assert_eq!(platform.firewall(), None);
                assert_eq!(platform.dhcp(), None);
                assert!(entry.contains("firewall: none  # or nftables\n"), "{entry}");
                assert!(entry.contains("dhcp: none  # or dnsmasq\n"), "{entry}");
                assert!(entry.contains("dns: none  # or dnsmasq\n"), "{entry}");
            }
        }
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
    wanZone: wan
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
    wanZone: wan
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
    fn on_linux_splot_applies_only_what_it_manages_there() {
        // On OpenWrt everything. On Linux the WireGuard so far: a node that asks
        // splot for its firewall or DHCP there is refused, not half applied.
        // DNS generates nothing on any platform yet.
        let linux = |name: &str, key: char, ip: u8, platform: &str| {
            format!(
                "
  {name}:
    platform:
      os: linux
{platform}
    publicKey: {}A=
    listenPort: 51820
    meshIp: 10.100.0.{ip}
",
                key.to_string().repeat(42)
            )
        };
        let network = checked(&format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
{}{}{}{}",
            linux(
                "Barn",
                'B',
                2,
                "      wireguard: wg-quick\n      firewall: none\n      dhcp: none\n      dns: dnsmasq"
            ),
            linux(
                "Lake",
                'C',
                3,
                "      wireguard: none\n      firewall: none\n      dhcp: none\n      dns: none"
            ),
            linux(
                "Mill",
                'D',
                4,
                "      wireguard: wg-quick\n      firewall: nftables\n      dhcp: none\n      dns: none"
            ),
            linux(
                "Pond",
                'E',
                5,
                "      wireguard: wg-quick\n      firewall: nftables\n      dhcp: dnsmasq\n      dns: none"
            ),
        ));
        let applicable = |node: &str| {
            check_applicable(&network, &node.parse().unwrap()).map_err(|err| err.to_string())
        };

        assert!(applicable("Home").is_ok());
        assert!(applicable("Barn").is_ok());
        assert!(applicable("Lake").is_ok());
        assert_eq!(
            applicable("Mill").unwrap_err(),
            "splot can't manage Mill's firewall (nftables) on Linux yet: set it to `none` to apply the rest"
        );
        assert_eq!(
            applicable("Pond").unwrap_err(),
            "splot can't manage Pond's firewall (nftables) or dhcp (dnsmasq) on Linux yet: set them to `none` to apply the rest"
        );
    }

    #[test]
    fn after_a_change_a_node_checks_the_other_nodes_at_their_mesh_ips() {
        // Not a global client or a hub client: one that's off doesn't make the
        // change wrong.
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
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
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
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
",
        );
        let probes = probes(&node_plan(&network, &"Home".parse().unwrap()).unwrap());

        let probes: Vec<String> = probes
            .iter()
            .map(|probe| format!("{} {}", probe.peer, probe.address))
            .collect();
        assert_eq!(probes, ["Cabin 10.100.0.2", "Lake 10.100.0.3"]);
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
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
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
