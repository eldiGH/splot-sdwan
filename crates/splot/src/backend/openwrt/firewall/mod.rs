mod deny;
mod listen_port;
mod ping;
mod redirect;
mod rules;
mod zones;

use std::{iter, sync::LazyLock};

use log::{Level, debug, info, log_enabled};
use splot_core::protocol::openwrt::{Crossing, Dest};

use super::{
    naming,
    section::{Section, UciSection},
};
use crate::{
    model::host::HostRef,
    plan::firewall::{FirewallPlan, Verdict, zone_ref::ZoneRef},
};
use zones::MeshZone;

pub(super) const FILE: &str = "firewall";

/// A host's part of a section id, with its node's name when it's inside a node,
/// so it can't clash with another node's host of the same name.
fn qualified_host_id(host: &HostRef) -> Vec<&str> {
    match host {
        HostRef::Local { node, name } => vec![node.as_ref(), name.as_ref()],
        _ => vec![host.name().as_ref()],
    }
}

/// splot's mesh zone as fw4 knows it, after the interface it covers.
static MESH_ZONE: LazyLock<String> = LazyLock::new(|| naming::mesh_interface().to_string());

/// A zone as fw4 knows it, by its `name`: splot's mesh zone after the interface
/// it covers, one of the operator's by its key in `splot.yml`.
fn zone_name(zone: &ZoneRef) -> &str {
    match zone {
        ZoneRef::Mesh => &MESH_ZONE,
        ZoneRef::Named(zone) => zone.as_ref(),
    }
}

/// A verdict as fw4 spells it.
fn target(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Drop => "DROP",
    }
}

/// The plan's firewall section as the `firewall` file's sections: the mesh zone,
/// the peers' ping and the listen port (if any), then the rules, splot's deny
/// after them, then the redirects, one for each WAN source of a forward, each
/// followed by its source NAT when it goes into the mesh to another host.
pub(super) fn render(firewall: &FirewallPlan) -> Vec<Section> {
    info!("Generating firewall config");
    info!(
        "  {} rule(s), {} redirect(s)",
        firewall.rules.len(),
        firewall.redirects.len()
    );

    if log_enabled!(Level::Debug) {
        for rule in &firewall.rules {
            debug!("  {rule}");
        }
        for redirect in &firewall.redirects {
            debug!("  {redirect}");
        }
    }

    let zone = firewall
        .mesh_zone
        .as_ref()
        .map(|policy| MeshZone(policy).to_section());
    let ping = firewall.ping.as_ref().map(|ping| ping.to_section());
    let listen_port = firewall
        .listen_port
        .as_ref()
        .map(|listen_port| listen_port.to_section());
    let rules = firewall.rules.iter().map(|rule| rule.to_section());
    let denies = deny::denies(&firewall.default_policy);
    let denies = denies.iter().map(|deny| deny.to_section());
    let redirects = firewall
        .redirects
        .iter()
        .flat_map(redirect::per_source)
        .flat_map(|redirect| {
            let snat = redirect.snat().map(|snat| snat.to_section());
            iter::once(redirect.to_section()).chain(snat)
        });

    zone.into_iter()
        .chain(ping)
        .chain(listen_port)
        .chain(rules)
        .chain(denies)
        .chain(redirects)
        .collect()
}

/// What splot decides in the node's firewall, as fw4 names the zones: what
/// its deny drops unless a service grants it, and the node's input from the
/// mesh zone, whose policy is splot's. The agent warns about the operator's own
/// sections there.
pub(super) fn owned(firewall: &FirewallPlan) -> Vec<Crossing> {
    let denied = deny::denies(&firewall.default_policy);
    let input = firewall.mesh_zone.as_ref().map(|_| Crossing {
        from: MESH_ZONE.clone(),
        to: Dest::Node,
    });

    denied
        .iter()
        .map(|deny| deny.crossing())
        .chain(input)
        .collect()
}

#[cfg(test)]
mod tests {
    use splot_core::uci::section::Value;

    use super::*;
    use crate::{plan, test_support::checked};

    /// The value of `option` in each of `sections` of type `section_type`.
    fn values<'a>(sections: &'a [Section], section_type: &str, option: &str) -> Vec<&'a str> {
        sections
            .iter()
            .filter(|section| section.section_type == section_type)
            .flat_map(|section| &section.options)
            .filter_map(|(name, value)| match value {
                Value::Single(value) if name == option => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_redirect_into_the_mesh_names_the_mesh_zone_as_fw4_knows_it() {
        // fw4 knows a zone by its `name`: a redirect naming any other resolves to
        // nothing. The camera on Home's hub is reached over the mesh.
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
    wanZone: wan
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, wan: { via: Home } }
",
        );
        let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
        let sections = render(&plan.firewall.unwrap());

        assert_eq!(values(&sections, "zone", "name"), ["spl_mesh"]);
        assert_eq!(values(&sections, "redirect", "dest"), ["spl_mesh"]);
    }

    // Home: ssh on the router and a nas on its lan, both from Phone; a camera on
    // its hub, forwarded from the WAN; an iot zone. Cabin's lan reaches the nas.
    const SITES: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      ssh: { port: 22, proto: tcp, allowFrom: Phone }
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          nas:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
            services:
              https: { port: 443, proto: tcp, allowFrom: [Phone, Cabin.lan] }
      iot:
        address: 192.168.10.1/24
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, allowFrom: Phone, wan: { via: Home } }
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
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
";

    fn sections(node: &str) -> Vec<Section> {
        let plan = plan::plan(&checked(SITES), &node.parse().unwrap()).unwrap();
        render(&plan.firewall.unwrap())
    }

    #[test]
    fn every_rule_names_the_zones_it_crosses() {
        // `*` would match every zone, the WAN and the operator's own included:
        // only what leaves the mesh zone is splot's wherever it goes.
        for node in ["Home", "Cabin"] {
            let sections = sections(node);

            // The ping, the listen port and the rules; Cabin's lets its lan out.
            let rules = values(&sections, "rule", "src");
            assert!(rules.len() >= 3, "{node}: {rules:?}");
            let mut wildcards = Vec::new();
            for section in &sections {
                for (option, value) in &section.options {
                    let wildcard = match value {
                        Value::Single(value) => value == "*",
                        Value::List(values) => values.iter().any(|value| value == "*"),
                    };
                    if wildcard {
                        wildcards.push(format!("{}.{option}", section.name));
                    }
                }
            }
            assert_eq!(wildcards, ["spl_rule_deny_spl_mesh_to_any.dest"], "{node}");
        }
    }

    #[test]
    fn splots_deny_comes_after_its_accepts() {
        // fw4 takes a chain's rules in the order of the file: a deny first would
        // drop what a service grants.
        let sections = sections("Home");
        let rules: Vec<&str> = sections
            .iter()
            .filter(|section| section.section_type == "rule")
            .map(|section| section.name.as_str())
            .collect();
        let first_deny = rules
            .iter()
            .position(|rule| rule.starts_with("spl_rule_deny_"))
            .unwrap();
        assert!(
            rules[first_deny..]
                .iter()
                .all(|rule| rule.starts_with("spl_rule_deny_")),
            "{rules:?}"
        );
        assert!(
            rules[..first_deny]
                .iter()
                .any(|rule| rule.starts_with("spl_rule_in_")),
            "{rules:?}"
        );
    }

    #[test]
    fn the_wan_and_undeclared_zones_get_no_splot_rule() {
        // Every rule's zones are splot's: the mesh zone and the ones splot.yml
        // declares; `*` only where the mesh zone's traffic goes. The WAN only for
        // the listen port, as a redirect's source.
        let sections = sections("Home");
        let splots = ["spl_mesh", "lan", "iot", "*"];
        let mut others = Vec::new();
        for section in sections
            .iter()
            .filter(|section| section.section_type == "rule")
        {
            for (option, value) in &section.options {
                if let Value::Single(value) = value
                    && ["src", "dest"].contains(&option.as_str())
                    && !splots.contains(&value.as_str())
                {
                    others.push(format!("{}.{option}={value}", section.name));
                }
            }
        }
        assert_eq!(others, ["spl_rule_listen_port.src=wan"]);
        assert_eq!(values(&sections, "redirect", "src"), ["wan"]);
        // All of Home's splot zones are in it, so none is missing from `splots`.
        let dests = values(&sections, "rule", "dest");
        for zone in splots {
            assert!(dests.contains(&zone), "{zone}: {dests:?}");
        }
    }

    /// Each crossing in a few words: `lan -> iot`, `spl_mesh -> *`,
    /// `spl_mesh -> node`.
    fn crossings(owned: &[Crossing]) -> Vec<String> {
        owned
            .iter()
            .map(|crossing| {
                let to = match &crossing.to {
                    Dest::Zone(zone) => zone,
                    Dest::AnyZone => "*",
                    Dest::Node => "node",
                };
                format!("{} -> {to}", crossing.from)
            })
            .collect()
    }

    #[test]
    fn splot_owns_where_its_deny_drops_and_the_nodes_input_from_the_mesh() {
        let plan = plan::plan(&checked(SITES), &"Home".parse().unwrap()).unwrap();
        let firewall = plan.firewall.unwrap();
        let owned = crossings(&owned(&firewall));
        assert_eq!(
            owned,
            [
                "spl_mesh -> *",
                "iot -> spl_mesh",
                "iot -> lan",
                "lan -> spl_mesh",
                "lan -> iot",
                "spl_mesh -> node",
            ]
        );

        // Exactly where a deny rule drops: an operator's forwarding there
        // forwards nothing.
        let sections = render(&firewall);
        let denies: Vec<&Section> = sections
            .iter()
            .filter(|section| section.name.starts_with("spl_rule_deny_"))
            .collect();
        let denied: Vec<String> = denies
            .iter()
            .map(|deny| {
                let option = |option| values(std::slice::from_ref(*deny), "rule", option)[0];
                format!("{} -> {}", option("src"), option("dest"))
            })
            .collect();
        assert_eq!(denied, owned[..owned.len() - 1]);
    }

    #[test]
    fn without_its_mesh_zone_splot_owns_what_crosses_between_the_declared_zones() {
        // Its WireGuard left alone, the mesh arrives in a zone of the
        // operator's.
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
      wireguard: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
      iot:
        address: 192.168.10.1/24
",
        );
        let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();

        assert_eq!(
            crossings(&owned(&plan.firewall.unwrap())),
            ["iot -> lan", "lan -> iot"]
        );
    }
}
