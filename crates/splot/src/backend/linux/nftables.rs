//! The node's firewall as an nft file: splot's own table, `inet splot`,
//! replaced whole in one transaction.
//!
//! On a hook every table's base chains see a packet: an `accept` ends only the
//! chain it's in, a `drop` is final. So splot's chains accept by their policy
//! what isn't splot's, and end what is in a verdict of splot's own: its drops
//! hold whatever other tables say, its accepts let through what no other table
//! drops. A zone is the interfaces `platform.interfaces` names for it, the mesh
//! zone splot's mesh interface, matched by name (`iifname`), so the rules load
//! before an interface is up.

use std::collections::BTreeSet;

use splot_core::consts::MESH_DEVICE;

use crate::{
    model::platform::Platform,
    plan::firewall::{
        FirewallPlan, ListenPort, Ping, Verdict, ZonePolicy,
        redirect::Redirect,
        rules::{Destination, Direction, Rule},
        zone_ref::ZoneRef,
    },
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange, protocol::Protocol},
};

/// splot's table: of the `inet` family, so its interface matches cover IPv6
/// too.
const TABLE: &str = "inet splot";

/// `items` as nft matches them: one as it is, more as an anonymous set. None is
/// `{ }`, which nft refuses: a match is never left out, which would match
/// anything.
fn set(items: Vec<String>) -> String {
    match items.as_slice() {
        [one] => one.clone(),
        _ if items.is_empty() => "{ }".to_owned(),
        _ => format!("{{ {} }}", items.join(", ")),
    }
}

/// `networks` as nft matches addresses: each once, a host as its address, and
/// none that another of them covers, so a set's elements never overlap,
/// whatever an nft version makes of that.
fn addresses(networks: &[Ipv4Network]) -> String {
    let networks: BTreeSet<&Ipv4Network> = networks.iter().collect();
    let shown = networks
        .iter()
        .filter(|network| {
            !networks
                .iter()
                .any(|other| other != *network && other.contains_network(***network))
        })
        .map(|network| {
            if **network == Ipv4Network::host(network.ip()) {
                network.ip().to_string()
            } else {
                network.to_string()
            }
        })
        .collect();

    set(shown)
}

/// What a rule matches of `protocol`, to `port`: TCP and UDP by port, ICMP
/// whole, since it has none (as fw4 takes a service's ICMP).
fn protocol(protocol: Protocol, port: &PortOrRange) -> String {
    match protocol {
        Protocol::Tcp | Protocol::Udp => format!("{protocol} dport {port}"),
        Protocol::Icmp => "meta l4proto icmp".to_owned(),
    }
}

fn verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
    }
}

/// A rule of a chain, under a comment saying what it's for.
struct Line {
    comment: String,
    rule: String,
}

/// A base chain of splot's table: its rules, in order.
struct Chain {
    name: &'static str,
    /// Its type, hook and priority: `filter hook input priority filter`.
    hook: &'static str,
    lines: Vec<Line>,
}

impl Chain {
    fn new(name: &'static str, hook: &'static str) -> Self {
        Self {
            name,
            hook,
            lines: Vec::new(),
        }
    }

    fn push(&mut self, comment: impl Into<String>, rule: String) {
        self.lines.push(Line {
            comment: comment.into(),
            rule,
        });
    }

    /// Its text: none without a rule. Its policy accepts what isn't splot's;
    /// what is ends in a rule's verdict.
    fn text(&self) -> String {
        if self.lines.is_empty() {
            return String::new();
        }

        let mut text = format!(
            "\n\tchain {} {{\n\t\ttype {}; policy accept;\n",
            self.name, self.hook
        );
        for Line { comment, rule } in &self.lines {
            text.push_str(&format!("\t\t# {comment}\n\t\t{rule}\n"));
        }
        text.push_str("\t}\n");
        text
    }
}

/// The interfaces of the node's zones, as rules match them.
struct Zones<'a> {
    platform: &'a Platform,
}

impl Zones<'_> {
    /// The interfaces `zone` is on: the mesh zone's is splot's mesh interface.
    fn of(&self, zone: &ZoneRef) -> String {
        match zone {
            ZoneRef::Mesh => format!("\"{MESH_DEVICE}\""),
            ZoneRef::Named(zone) => self.named(zone),
        }
    }

    /// The interfaces of `zone`, one of the node's zones or its wanZone.
    fn named(&self, zone: &Identifier) -> String {
        let interfaces = self
            .platform
            .interfaces(zone)
            .expect("an nftables node has interfaces for each of its zones and its wanZone");
        set(interfaces
            .iter()
            .map(|interface| format!("\"{interface}\""))
            .collect())
    }
}

/// A rule's label, in the config's notation: `in: Barn ssh, from spl_mesh`,
/// and `in: Cabin.camera rtsp, via Home` for Home's forward.
fn label(rule: &Rule) -> String {
    let direction = match rule.direction {
        Direction::Ingress => "in",
        Direction::Egress => "out",
    };
    let whence = match &rule.via {
        Some(via) => format!("via {via}"),
        None => format!("from {}", from_name(&rule.from)),
    };
    format!("{direction}: {} {}, {whence}", rule.host, rule.service)
}

/// A zone's name in a label: the mesh zone's by its interface, as fw4's.
fn from_name(zone: &ZoneRef) -> String {
    match zone {
        ZoneRef::Mesh => MESH_DEVICE.to_owned(),
        ZoneRef::Named(zone) => zone.to_string(),
    }
}

/// A forward's label: `Cabin.weather http`.
fn forward_label(redirect: &Redirect) -> String {
    format!("{} {}", redirect.host, redirect.service)
}

/// The forward's match of its WAN sources: none when it has none.
fn wan_sources(redirect: &Redirect) -> String {
    if redirect.sources.is_empty() {
        String::new()
    } else {
        format!(" ip saddr {}", addresses(&redirect.sources))
    }
}

/// `node`'s firewall plan as the nft file of splot's table, its zones on the
/// interfaces `platform` says.
pub(super) fn render(node: &Identifier, firewall: &FirewallPlan, platform: &Platform) -> String {
    let zones = Zones { platform };
    let mesh = zones.of(&ZoneRef::Mesh);

    let mut input = Chain::new("input", "filter hook input priority filter");
    let mut forward = Chain::new("forward", "filter hook forward priority filter");
    let mut output = Chain::new("output", "filter hook output priority filter");
    let mut dstnat = Chain::new("dstnat", "nat hook prerouting priority dstnat");
    let mut srcnat = Chain::new("srcnat", "nat hook postrouting priority srcnat");

    if let Some(Ping { to, from }) = &firewall.ping {
        let from: Vec<Ipv4Network> = from
            .iter()
            .map(|(_, address)| Ipv4Network::host(*address))
            .collect();
        input.push(
            "ping from its peers",
            format!(
                "iifname {mesh} ip saddr {} ip daddr {to} icmp type echo-request accept",
                addresses(&from)
            ),
        );
    }
    if let Some(ListenPort { wan_zone, port }) = &firewall.listen_port {
        input.push(
            "WireGuard listen port",
            format!("iifname {} udp dport {port} accept", zones.named(wan_zone)),
        );
    }

    for rule in &firewall.rules {
        let (chain, oifname) = match &rule.to {
            Destination::Node => (&mut input, String::new()),
            Destination::Zone(to) => (&mut forward, format!(" oifname {}", zones.of(to))),
        };
        for proto in &rule.proto {
            chain.push(
                label(rule),
                format!(
                    "iifname {}{oifname} ip saddr {} ip daddr {} {} accept",
                    zones.of(&rule.from),
                    addresses(&rule.sources),
                    addresses(&rule.destinations),
                    protocol(*proto, &rule.port)
                ),
            );
        }
    }

    // The forwards, as translated: they cross a deny only where the WAN is on a
    // zone's interface (a host that isn't its site's gateway).
    for redirect in &firewall.redirects {
        let wan = zones.named(&redirect.wan_zone);
        let sources = wan_sources(redirect);
        let label = forward_label(redirect);
        for proto in &redirect.proto {
            dstnat.push(
                label.clone(),
                format!(
                    "iifname {wan}{sources} {} dnat ip to {}:{}",
                    protocol(*proto, &redirect.external_port),
                    redirect.dest_ip,
                    redirect.internal_port
                ),
            );
            forward.push(
                format!("from the WAN: {label}"),
                format!(
                    "iifname {wan}{sources} ip daddr {} {} ct status dnat accept",
                    redirect.dest_ip,
                    protocol(*proto, &redirect.internal_port)
                ),
            );
            if let Some(snat) = redirect.snat {
                srcnat.push(
                    format!("snat: {label}"),
                    format!(
                        "oifname {} ct status dnat{sources} ip daddr {} {} snat ip to {snat}",
                        zones.of(&redirect.dest_zone),
                        redirect.dest_ip,
                        protocol(*proto, &redirect.internal_port)
                    ),
                );
            }
        }
    }

    if let Some(ZonePolicy {
        input: to_node,
        output: from_node,
        forward: within,
    }) = firewall.mesh_zone
    {
        input.push(
            "the mesh zone's input",
            format!("iifname {mesh} {}", verdict(to_node)),
        );
        output.push(
            "the mesh zone's output",
            format!("oifname {mesh} {}", verdict(from_node)),
        );
        forward.push(
            "within the mesh zone",
            format!("iifname {mesh} oifname {mesh} {}", verdict(within)),
        );
    }

    let policy = &firewall.default_policy;
    for (from, to) in policy.crossings() {
        let (comment, oifname) = match to {
            Some(to) => (
                format!("deny: {} to {}", from_name(from), from_name(to)),
                format!(" oifname {}", zones.of(to)),
            ),
            None => (
                format!("deny: {} to any zone", from_name(from)),
                String::new(),
            ),
        };
        forward.push(
            comment,
            format!(
                "iifname {}{oifname} {}",
                zones.of(from),
                verdict(policy.verdict)
            ),
        );
    }

    // What came back for what was let through.
    for chain in [&mut input, &mut forward] {
        if !chain.lines.is_empty() {
            chain.lines.insert(
                0,
                Line {
                    comment: "replies, and what they bring".to_owned(),
                    rule: "ct state established,related accept".to_owned(),
                },
            );
        }
    }

    let mut file = format!(
        "# The firewall of node {node}, written by splot: its own table, which
# `splot apply` replaces whole. Change splot.yml instead.
table {TABLE}
delete table {TABLE}

table {TABLE} {{"
    );
    for chain in [input, forward, output, dstnat, srcnat] {
        file.push_str(&chain.text());
    }
    file.push_str("}\n");
    file
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support::checked};

    // Barn, on Linux, lets Phone in to its ssh and its nvr's web page, which it
    // forwards from two WAN sources; its iot zone is on two interfaces. Cabin's
    // camera takes rtsp from Barn's nvr, and Barn forwards Cabin's weather
    // station from anywhere.
    const MESH: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Barn:
    platform:
      os: linux
      wireguard: wg-quick
      firewall: nftables
      dhcp: none
      dns: none
      interfaces:
        lan: eth0
        iot: [eth0.20, wlan1]
        wan: eth1
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.4
    wanZone: wan
    services:
      ssh: { port: 22, proto: tcp, allowFrom: Phone }
    zones:
      lan:
        address: 192.168.4.1/24
        devices:
          nvr:
            ip: 192.168.4.10
            macs: aa:bb:cc:00:00:07
            services:
              web:
                port: '8443:443'
                proto: tcp
                allowFrom: Phone
                wan: { via: Barn, sources: [198.51.100.0/24, 203.0.113.7/32] }
      iot:
        address: 192.168.40.1/24
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          camera:
            ip: 192.168.2.30
            macs: aa:bb:cc:00:00:04
            services:
              rtsp: { port: 554, proto: [tcp, udp], allowFrom: Barn.nvr }
          weather:
            ip: 192.168.2.40
            macs: aa:bb:cc:00:00:06
            services:
              http: { port: '8080:80', proto: tcp, wan: { via: Barn } }
clients:
  Phone:
    publicKey: PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPA=
    meshIp: 10.100.1.10
";

    /// Barn's nft file, of the mesh `yaml`.
    fn barn(yaml: &str) -> String {
        let network = checked(yaml);
        let barn = network.node(&"Barn".parse().unwrap()).unwrap();
        let plan = plan::plan(&network, barn.name()).unwrap();

        render(
            barn.name(),
            plan.firewall.as_ref().unwrap(),
            barn.platform(),
        )
    }

    /// The rules of chain `name` in `file`, in order: without its type, and
    /// without the comments.
    fn chain(file: &str, name: &str) -> Vec<String> {
        let start = format!("\tchain {name} {{");
        file.lines()
            .skip_while(|line| *line != start)
            .skip(1)
            .take_while(|line| *line != "\t}")
            .map(str::trim)
            .filter(|line| !line.starts_with("type ") && !line.starts_with('#'))
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn the_file_replaces_splots_table_whole_and_touches_no_other() {
        let file = barn(MESH);
        let tables: Vec<&str> = file
            .lines()
            .filter(|line| line.contains("table"))
            .filter(|line| !line.starts_with('#'))
            .collect();

        // Made if it isn't there, deleted, and written again: one transaction
        // with `nft -f`, whether the table was there or not.
        assert_eq!(
            tables,
            [
                "table inet splot",
                "delete table inet splot",
                "table inet splot {"
            ]
        );
        assert!(!file.contains("flush"), "{file}");
        assert!(file.ends_with("}\n"), "{file}");
    }

    #[test]
    fn the_chains_accept_what_isnt_splots_and_run_at_the_usual_priorities() {
        let file = barn(MESH);
        for (chain, hook) in [
            (
                "input",
                "type filter hook input priority filter; policy accept;",
            ),
            (
                "forward",
                "type filter hook forward priority filter; policy accept;",
            ),
            (
                "output",
                "type filter hook output priority filter; policy accept;",
            ),
            (
                "dstnat",
                "type nat hook prerouting priority dstnat; policy accept;",
            ),
            (
                "srcnat",
                "type nat hook postrouting priority srcnat; policy accept;",
            ),
        ] {
            let header = format!("\tchain {chain} {{\n\t\t{hook}\n");
            assert!(file.contains(&header), "{chain}: {file}");
        }
    }

    #[test]
    fn the_node_takes_from_the_mesh_what_its_rules_let_in_and_drops_the_rest() {
        assert_eq!(
            chain(&barn(MESH), "input"),
            [
                "ct state established,related accept",
                // Its peers' ping.
                "iifname \"spl_mesh\" ip saddr { 10.100.0.2, 10.100.1.10 } ip daddr 10.100.0.4 icmp type echo-request accept",
                // The listen port, from the WAN.
                "iifname \"eth1\" udp dport 51820 accept",
                // Phone's ssh, to the node's own addresses.
                "iifname \"spl_mesh\" ip saddr 10.100.1.10 ip daddr { 10.100.0.4, 192.168.4.1, 192.168.40.1 } tcp dport 22 accept",
                // The mesh zone's input.
                "iifname \"spl_mesh\" drop",
            ]
        );
    }

    #[test]
    fn what_crosses_the_node_is_let_through_by_its_rules_then_dropped_between_its_zones() {
        assert_eq!(
            chain(&barn(MESH), "forward"),
            [
                "ct state established,related accept",
                // Phone to the nvr's web page, from the mesh into lan.
                "iifname \"spl_mesh\" oifname \"eth0\" ip saddr 10.100.1.10 ip daddr 192.168.4.10 tcp dport 443 accept",
                // The nvr to Cabin's camera: one rule a protocol.
                "iifname \"eth0\" oifname \"spl_mesh\" ip saddr 192.168.4.10 ip daddr 192.168.2.30 tcp dport 554 accept",
                "iifname \"eth0\" oifname \"spl_mesh\" ip saddr 192.168.4.10 ip daddr 192.168.2.30 udp dport 554 accept",
                // The forwards from the WAN, as translated.
                "iifname \"eth1\" ip saddr { 198.51.100.0/24, 203.0.113.7 } ip daddr 192.168.4.10 tcp dport 443 ct status dnat accept",
                "iifname \"eth1\" ip daddr 192.168.2.40 tcp dport 80 ct status dnat accept",
                // The mesh zone's forward, within it.
                "iifname \"spl_mesh\" oifname \"spl_mesh\" drop",
                // splot's deny: out of the mesh, and between the declared zones.
                "iifname \"spl_mesh\" drop",
                "iifname { \"eth0.20\", \"wlan1\" } oifname \"spl_mesh\" drop",
                "iifname { \"eth0.20\", \"wlan1\" } oifname \"eth0\" drop",
                "iifname \"eth0\" oifname \"spl_mesh\" drop",
                "iifname \"eth0\" oifname { \"eth0.20\", \"wlan1\" } drop",
            ]
        );
    }

    #[test]
    fn what_the_node_sends_into_the_mesh_is_accepted() {
        assert_eq!(
            chain(&barn(MESH), "output"),
            ["oifname \"spl_mesh\" accept"]
        );
    }

    #[test]
    fn a_forward_is_translated_from_its_wan_sources_and_into_the_mesh_sent_as_the_node() {
        let file = barn(MESH);
        assert_eq!(
            chain(&file, "dstnat"),
            [
                "iifname \"eth1\" ip saddr { 198.51.100.0/24, 203.0.113.7 } tcp dport 8443 dnat ip to 192.168.4.10:443",
                "iifname \"eth1\" tcp dport 8080 dnat ip to 192.168.2.40:80",
            ]
        );
        // Only what was forwarded: what the node's own networks send there keeps
        // its address.
        assert_eq!(
            chain(&file, "srcnat"),
            [
                "oifname \"spl_mesh\" ct status dnat ip daddr 192.168.2.40 tcp dport 80 snat ip to 10.100.0.4"
            ]
        );
    }

    #[test]
    fn a_forward_into_the_mesh_from_some_sources_is_sent_as_the_node_from_those() {
        let yaml = MESH.replace(
            "wan: { via: Barn } }",
            "wan: { via: Barn, sources: 198.51.100.0/24 } }",
        );
        assert_eq!(
            chain(&barn(&yaml), "srcnat"),
            [
                "oifname \"spl_mesh\" ct status dnat ip saddr 198.51.100.0/24 ip daddr 192.168.2.40 tcp dport 80 snat ip to 10.100.0.4"
            ]
        );
    }

    #[test]
    fn a_node_without_forwards_has_no_nat_chains() {
        let yaml = MESH
            .replace(
                "                wan: { via: Barn, sources: [198.51.100.0/24, 203.0.113.7/32] }\n",
                "",
            )
            .replace(", wan: { via: Barn } }", ", allowFrom: Phone }");
        let file = barn(&yaml);

        assert!(file.contains("\tchain forward {"), "{file}");
        assert!(!file.contains("chain dstnat"), "{file}");
        assert!(!file.contains("chain srcnat"), "{file}");
        assert!(!file.contains("ct status dnat"), "{file}");
    }

    #[test]
    fn without_splots_wireguard_there_is_no_mesh_zone_only_the_declared_ones() {
        let yaml = MESH
            .replace("      wireguard: wg-quick\n", "      wireguard: none\n")
            .replace(", wan: { via: Barn } }", ", allowFrom: Phone }");
        let file = barn(&yaml);

        assert!(!file.contains("spl_mesh"), "{file}");
        assert!(!file.contains("chain input"), "{file}");
        assert!(!file.contains("chain output"), "{file}");
        assert_eq!(
            chain(&file, "forward"),
            [
                "ct state established,related accept",
                // The nvr's forward is into lan, not the mesh: it stays.
                "iifname \"eth1\" ip saddr { 198.51.100.0/24, 203.0.113.7 } ip daddr 192.168.4.10 tcp dport 443 ct status dnat accept",
                "iifname { \"eth0.20\", \"wlan1\" } oifname \"eth0\" drop",
                "iifname \"eth0\" oifname { \"eth0.20\", \"wlan1\" } drop",
            ]
        );
    }

    #[test]
    fn each_rule_is_under_a_comment_in_the_configs_notation() {
        let file = barn(MESH);
        for comment in [
            "\t\t# ping from its peers\n\t\tiifname \"spl_mesh\" ip saddr",
            "\t\t# WireGuard listen port\n\t\tiifname \"eth1\" udp",
            "\t\t# in: Barn ssh, from spl_mesh\n\t\tiifname \"spl_mesh\" ip saddr 10.100.1.10",
            "\t\t# out: Cabin.camera rtsp, from lan\n\t\tiifname \"eth0\" oifname \"spl_mesh\" ip saddr 192.168.4.10 ip daddr 192.168.2.30 tcp",
            "\t\t# deny: iot to lan\n\t\tiifname { \"eth0.20\", \"wlan1\" } oifname \"eth0\" drop",
            "\t\t# Cabin.weather http\n\t\tiifname \"eth1\" tcp dport 8080",
            "\t\t# snat: Cabin.weather http\n\t\toifname \"spl_mesh\" ct status dnat",
        ] {
            assert!(file.contains(comment), "{comment}\n{file}");
        }
    }

    #[test]
    fn addresses_are_written_once_and_none_another_covers() {
        let networks = |list: &[&str]| -> Vec<Ipv4Network> {
            list.iter()
                .map(|network| network.parse().unwrap())
                .collect()
        };

        assert_eq!(addresses(&networks(&["10.0.0.1/32"])), "10.0.0.1");
        assert_eq!(
            addresses(&networks(&["10.0.0.0/24", "10.1.0.1/32"])),
            "{ 10.0.0.0/24, 10.1.0.1 }"
        );
        // The covering network is enough, whichever comes first: a set's
        // elements never overlap.
        for list in [
            ["192.168.1.0/24", "192.168.1.50/32"],
            ["192.168.1.50/32", "192.168.1.0/24"],
        ] {
            assert_eq!(addresses(&networks(&list)), "192.168.1.0/24");
        }
        assert_eq!(
            addresses(&networks(&["10.0.0.1/32", "10.0.0.1/32"])),
            "10.0.0.1"
        );
    }

    #[test]
    fn a_match_on_nothing_is_one_nft_refuses_never_one_on_anything() {
        assert_eq!(addresses(&[]), "{ }");
        assert_eq!(set(Vec::new()), "{ }");
    }

    #[test]
    fn icmp_is_matched_whole_tcp_and_udp_by_port() {
        let port = "53".parse().unwrap();
        assert_eq!(protocol(Protocol::Tcp, &port), "tcp dport 53");
        assert_eq!(protocol(Protocol::Udp, &port), "udp dport 53");
        // It has no ports: as fw4 takes one in a rule.
        assert_eq!(protocol(Protocol::Icmp, &port), "meta l4proto icmp");
        let range = "1000-1010".parse().unwrap();
        assert_eq!(protocol(Protocol::Tcp, &range), "tcp dport 1000-1010");
    }
}
