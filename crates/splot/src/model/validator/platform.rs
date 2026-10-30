//! Platforms: which software runs each node, and which concerns splot manages
//! there.

use std::collections::BTreeMap;

use splot_core::consts::MESH_DEVICE;

use crate::{
    config::{self, Config},
    consts,
    model::{
        platform::Platform,
        validator::types::{ValidationError, ValidationReport},
    },
    types::{
        config_location::{ConfigLocation, HubLoc, NodeLoc, PlatformLoc, ZoneLoc},
        identifier::Identifier,
        interface::InterfaceName,
        platform::{FirewallProgram, Os, Program, Setting, names},
    },
};

/// Every node's platform that passes its checks: each concern's program runs on
/// the node's OS, and a concern left out has a default there (an OpenWrt node's;
/// a Linux node has none). A node whose WireGuard splot leaves alone has no hub:
/// hub clients are peers on splot's mesh interface.
pub(super) fn check_platforms(
    config: &Config,
    report: &mut ValidationReport,
) -> BTreeMap<Identifier, Platform> {
    config
        .nodes
        .iter()
        .filter_map(|(name, node)| {
            let platform = check_platform(name, &node.platform, report)?;

            if platform.wireguard.is_none() && node.hub.is_some() {
                report.errors.push(ValidationError::HubWithoutWireGuard {
                    at: ConfigLocation::Node(name.clone(), NodeLoc::Hub(HubLoc::Root)),
                });
            }
            if platform.firewall == Some(FirewallProgram::Fw4) {
                check_fw4_zone_names(name, node, report);
            }
            check_interfaces(name, node, &platform, report);

            Some((name.clone(), platform))
        })
        .collect()
}

/// On OpenWrt a zone's key is the name of its fw4 zone, and so is `wanZone`.
/// fw4's names can't start with a digit; a name in `splot.yml` may.
fn check_fw4_zone_names(name: &Identifier, node: &config::Node, report: &mut ValidationReport) {
    let zones = node
        .zones
        .keys()
        .map(|zone| (zone, NodeLoc::Zone(zone.clone(), ZoneLoc::Root)));
    let wan_zone = node.wan_zone.iter().map(|zone| (zone, NodeLoc::WanZone));

    for (zone, at) in zones.chain(wan_zone) {
        if zone.as_ref().starts_with(|c: char| c.is_ascii_digit()) {
            report.errors.push(ValidationError::Fw4ZoneName {
                zone: zone.clone(),
                at: ConfigLocation::Node(name.clone(), at),
            });
        }
    }
}

/// The interfaces nftables tells a Linux node's zones apart by: each zone, and
/// the wanZone, on interfaces of its own, which an nftables node names for
/// every one. The WAN may come in on a zone's: a host that isn't its site's
/// gateway. An OpenWrt node's zones are its fw4 zones of the same name.
fn check_interfaces(
    name: &Identifier,
    node: &config::Node,
    platform: &Platform,
    report: &mut ValidationReport,
) {
    let interfaces = &node.platform.interfaces;
    let at = |loc| ConfigLocation::Node(name.clone(), NodeLoc::Platform(loc));

    if platform.os == Os::OpenWrt {
        if !interfaces.is_empty() {
            report.errors.push(ValidationError::InterfacesOnOpenWrt {
                at: at(PlatformLoc::Interfaces),
            });
        }
        return;
    }

    let is_zone = |zone: &Identifier| node.zones.contains_key(zone);
    for (zone, on) in interfaces {
        if !is_zone(zone) && node.wan_zone.as_ref() != Some(zone) {
            report.errors.push(ValidationError::InterfaceOfNoZone {
                zone: zone.clone(),
                at: at(PlatformLoc::Interface(zone.clone())),
            });
        }
        if on.iter().any(|interface| interface.as_str() == MESH_DEVICE) {
            report.errors.push(ValidationError::MeshDeviceInZone {
                at: at(PlatformLoc::Interface(zone.clone())),
            });
        }
    }

    let mut zones_on: BTreeMap<&InterfaceName, Vec<&Identifier>> = BTreeMap::new();
    for (zone, on) in interfaces.iter().filter(|(zone, _)| is_zone(zone)) {
        for interface in on {
            zones_on.entry(interface).or_default().push(zone);
        }
    }
    for (interface, zones) in zones_on {
        if zones.len() > 1 {
            let zones: Vec<String> = zones.iter().map(ToString::to_string).collect();
            report.errors.push(ValidationError::SharedInterface {
                interface: interface.clone(),
                zones: zones.join(", "),
                at: at(PlatformLoc::Interfaces),
            });
        }
    }

    if platform.firewall == Some(FirewallProgram::Nftables) {
        for zone in node.zones.keys().chain(&node.wan_zone) {
            if !interfaces.contains_key(zone) {
                report.errors.push(ValidationError::ZoneWithoutInterface {
                    zone: zone.clone(),
                    at: at(PlatformLoc::Interfaces),
                });
            }
        }
    }
}

fn check_platform(
    node: &Identifier,
    platform: &config::Platform,
    report: &mut ValidationReport,
) -> Option<Platform> {
    let os = platform.os;
    // Each concern checked before any is given up on, so all are reported.
    let wireguard = concern(
        node,
        os,
        platform.wireguard,
        consts::OPENWRT_WIREGUARD,
        report,
    );
    let firewall = concern(
        node,
        os,
        platform.firewall,
        consts::OPENWRT_FIREWALL,
        report,
    );
    let dhcp = concern(node, os, platform.dhcp, consts::OPENWRT_DHCP, report);
    let dns = concern(node, os, platform.dns, consts::OPENWRT_DNS, report);

    Some(Platform {
        os,
        wireguard: wireguard?,
        firewall: firewall?,
        dhcp: dhcp?,
        dns: dns?,
        ssh: platform.ssh.clone(),
    })
}

/// The program behind one concern of a node on `os`, none when splot leaves the
/// concern alone; reported and given up on when the setting doesn't work there.
fn concern<P: Program>(
    node: &Identifier,
    os: Os,
    setting: Option<Setting<P>>,
    openwrt_default: P,
    report: &mut ValidationReport,
) -> Option<Option<P>> {
    let at = |loc| ConfigLocation::Node(node.clone(), NodeLoc::Platform(loc));

    match setting {
        Some(Setting::None) => Some(None),
        Some(Setting::Program(program)) if program.runs_on(os) => Some(Some(program)),
        Some(Setting::Program(program)) => {
            report.errors.push(ValidationError::UnsupportedProgram {
                concern: P::CONCERN,
                program: program.to_string(),
                os,
                choices: names(P::ALL.iter().copied().filter(|p| p.runs_on(os))),
                at: at(PlatformLoc::Concern(P::CONCERN)),
            });
            None
        }
        None => match os {
            Os::OpenWrt => Some(Some(openwrt_default)),
            Os::Linux => {
                report.errors.push(ValidationError::ConcernMissing {
                    concern: P::CONCERN,
                    os,
                    at: at(PlatformLoc::Root),
                });
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::{config, error_at, report},
        types::platform::{Concern, DhcpProgram, DnsProgram, FirewallProgram, WireGuardProgram},
    };

    /// A mesh of Home, whose `platform` block is `platform`.
    fn home(platform: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
{platform}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
"
        )
    }

    /// Home's platform, checked; panics on a diagnostic.
    fn platform(lines: &str) -> Platform {
        let config = config(&home(lines));
        let mut report = ValidationReport::default();
        let platforms = check_platforms(&config, &mut report);

        assert!(
            report.errors.is_empty(),
            "{:?}",
            report
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
        platforms[&"Home".parse::<Identifier>().unwrap()].clone()
    }

    #[test]
    fn an_openwrt_node_runs_what_openwrt_ships_unless_told_otherwise() {
        assert_eq!(
            platform("      os: openwrt"),
            Platform {
                os: Os::OpenWrt,
                wireguard: Some(WireGuardProgram::Netifd),
                firewall: Some(FirewallProgram::Fw4),
                dhcp: Some(DhcpProgram::Dnsmasq),
                dns: Some(DnsProgram::Dnsmasq),
                ssh: None,
            }
        );
        // Spelled out, the same.
        assert_eq!(
            platform(
                "      os: openwrt
      wireguard: netifd
      firewall: fw4
      dhcp: dnsmasq
      dns: dnsmasq"
            ),
            platform("      os: openwrt")
        );
    }

    #[test]
    fn none_leaves_a_concern_alone() {
        assert_eq!(
            platform(
                "      os: openwrt
      firewall: none
      dhcp: none"
            ),
            Platform {
                os: Os::OpenWrt,
                wireguard: Some(WireGuardProgram::Netifd),
                firewall: None,
                dhcp: None,
                dns: Some(DnsProgram::Dnsmasq),
                ssh: None,
            }
        );
        assert_eq!(
            platform(
                "      os: openwrt
      wireguard: none
      dns: none"
            ),
            Platform {
                os: Os::OpenWrt,
                wireguard: None,
                firewall: Some(FirewallProgram::Fw4),
                dhcp: Some(DhcpProgram::Dnsmasq),
                dns: None,
                ssh: None,
            }
        );
    }

    #[test]
    fn a_linux_node_names_every_concern() {
        assert_eq!(
            platform(
                "      os: linux
      wireguard: wg-quick
      firewall: none
      dhcp: dnsmasq
      dns: none"
            ),
            Platform {
                os: Os::Linux,
                wireguard: Some(WireGuardProgram::WgQuick),
                firewall: None,
                dhcp: Some(DhcpProgram::Dnsmasq),
                dns: None,
                ssh: None,
            }
        );

        // Each one left out is reported, at the block.
        let r = report(&home(
            "      os: linux
      wireguard: wg-quick
      dhcp: dnsmasq",
        ));
        let missing = |concern| {
            error_at(
                &r,
                "nodes.Home.platform",
                |e| matches!(e, ValidationError::ConcernMissing { concern: c, .. } if *c == concern),
            )
        };
        assert!(missing(Concern::Firewall));
        assert!(missing(Concern::Dns));
        assert_eq!(r.errors.len(), 2);
    }

    #[test]
    fn a_program_the_os_doesnt_have_is_an_error() {
        let r = report(&home(
            "      os: openwrt
      wireguard: wg-quick
      firewall: nftables
      dhcp: dnsmasq",
        ));
        let unsupported = |concern: &str, program: &str| {
            error_at(
                &r,
                &format!("nodes.Home.platform.{concern}"),
                |e| matches!(e, ValidationError::UnsupportedProgram { program: p, .. } if p == program),
            )
        };
        assert!(unsupported("wireguard", "wg-quick"));
        assert!(unsupported("firewall", "nftables"));
        assert_eq!(r.errors.len(), 2);

        let r = report(&home(
            "      os: linux
      wireguard: netifd
      firewall: fw4
      dhcp: dnsmasq
      dns: dnsmasq",
        ));
        let messages: Vec<String> = r.errors.iter().map(ToString::to_string).collect();
        assert_eq!(
            messages,
            [
                "nodes.Home.platform.wireguard: splot can't manage wireguard with netifd on linux - there it's wg-quick, or none",
                "nodes.Home.platform.firewall: splot can't manage firewall with fw4 on linux - there it's nftables, or none",
            ]
        );
    }

    #[test]
    fn a_node_whose_wireguard_splot_leaves_alone_has_no_hub() {
        let hub = "
    hub:
      network: 10.100.49.0/24
";
        let hub_error = |platform: &str| {
            let r = report(&format!("{}{hub}", home(platform)));
            error_at(&r, "nodes.Home.hub", |e| {
                matches!(e, ValidationError::HubWithoutWireGuard { .. })
            })
        };

        assert!(hub_error("      os: openwrt\n      wireguard: none"));
        assert!(!hub_error("      os: openwrt"));
        assert!(!hub_error("      os: openwrt\n      firewall: none"));
    }

    #[test]
    fn fw4_names_no_zone_after_a_digit() {
        // On OpenWrt a zone's key is its fw4 zone's name, and so is wanZone.
        let zones = "    zones:
      1lan: { address: 192.168.1.1/24 }
      lan2: { address: 192.168.2.1/24 }
";
        let errors = |platform: &str, wan_zone: &str| {
            let yaml =
                home(platform).replace("    wanZone: wan\n", &format!("    wanZone: {wan_zone}\n"));
            let r = report(&format!("{yaml}{zones}"));
            [
                "nodes.Home.zones.1lan",
                "nodes.Home.zones.lan2",
                "nodes.Home.wanZone",
            ]
            .into_iter()
            .filter(|at| error_at(&r, at, |e| matches!(e, ValidationError::Fw4ZoneName { .. })))
            .collect::<Vec<_>>()
        };

        assert_eq!(
            errors("      os: openwrt", "0wan"),
            ["nodes.Home.zones.1lan", "nodes.Home.wanZone"]
        );
        assert_eq!(
            errors("      os: openwrt", "wan"),
            ["nodes.Home.zones.1lan"]
        );
        // Where splot leaves the firewall alone, no fw4 zone is named after them.
        assert!(errors("      os: openwrt\n      firewall: none", "0wan").is_empty());
    }

    /// Home on Linux, with zones iot and lan and its wanZone, its firewall
    /// `firewall`, and `interfaces` (the lines of its key) in its platform.
    fn on_linux(firewall: &str, interfaces: &str) -> ValidationReport {
        let platform = format!(
            "      os: linux
      wireguard: wg-quick
      firewall: {firewall}
      dhcp: none
      dns: none
{interfaces}"
        );
        report(&format!(
            "{}    zones:
      iot: {{ address: 192.168.10.1/24 }}
      lan: {{ address: 192.168.1.1/24 }}
",
            home(&platform)
        ))
    }

    fn messages(r: &ValidationReport) -> Vec<String> {
        r.errors.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn an_nftables_node_says_which_interfaces_its_zones_are_on() {
        let r = on_linux(
            "nftables",
            "      interfaces:
        lan: eth0
        iot: [eth0.10, wlan0]
        wan: eth1",
        );
        assert!(r.errors.is_empty(), "{:?}", messages(&r));

        // The WAN may come in on a zone's: a host that isn't its site's gateway.
        let r = on_linux(
            "nftables",
            "      interfaces:
        lan: eth0
        iot: eth0.10
        wan: eth0",
        );
        assert!(r.errors.is_empty(), "{:?}", messages(&r));

        // A name Linux or nftables wouldn't take doesn't parse (serde says only
        // where: a key that takes one or a list doesn't pass on why).
        let err = serde_norway::from_str::<Config>(&home(
            "      os: linux\n      interfaces:\n        lan: eth*",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.starts_with("nodes.Home.platform.interfaces: "), "{err}");
    }

    #[test]
    fn an_nftables_node_needs_an_interface_for_each_zone_and_its_wan_zone() {
        // The zones named in each error, which all point at the key.
        let missing = |r: &ValidationReport| -> Vec<String> {
            let zones: Vec<String> = r
                .errors
                .iter()
                .filter_map(|e| match e {
                    ValidationError::ZoneWithoutInterface { zone, at } => {
                        assert_eq!(at.to_string(), "nodes.Home.platform.interfaces");
                        Some(zone.to_string())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(zones.len(), r.errors.len(), "{:?}", messages(r));
            zones
        };

        let r = on_linux("nftables", "      interfaces:\n        lan: eth0");
        assert_eq!(missing(&r), ["iot", "wan"]);
        let r = on_linux("nftables", "      interfaces:\n        wan: eth1");
        assert_eq!(missing(&r), ["iot", "lan"]);
        assert_eq!(missing(&on_linux("nftables", "")), ["iot", "lan", "wan"]);

        // Where splot leaves the firewall alone, nothing needs one.
        assert!(on_linux("none", "").errors.is_empty());
        assert!(
            on_linux("none", "      interfaces:\n        lan: eth0")
                .errors
                .is_empty()
        );
    }

    #[test]
    fn an_interface_is_for_a_zone_of_the_node_or_its_wan_zone() {
        for firewall in ["nftables", "none"] {
            let r = on_linux(
                firewall,
                "      interfaces:
        lan: eth0
        iot: eth0.10
        wan: eth1
        lab: eth2",
            );
            assert!(error_at(&r, "nodes.Home.platform.interfaces.lab", |e| {
                matches!(e, ValidationError::InterfaceOfNoZone { zone, .. } if zone.as_ref() == "lab")
            }));
            assert_eq!(r.errors.len(), 1, "{firewall}: {:?}", messages(&r));
        }
    }

    #[test]
    fn two_zones_on_one_interface_is_an_error() {
        // The interface each error names, and its zones.
        let shared = |interfaces: &str| -> Vec<(String, String)> {
            let r = on_linux("nftables", interfaces);
            let shared: Vec<(String, String)> = r
                .errors
                .iter()
                .filter_map(|e| match e {
                    ValidationError::SharedInterface {
                        interface,
                        zones,
                        at,
                    } => {
                        assert_eq!(at.to_string(), "nodes.Home.platform.interfaces");
                        Some((interface.to_string(), zones.clone()))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(shared.len(), r.errors.len(), "{:?}", messages(&r));
            shared
        };
        let pair = |interface: &str| vec![(interface.to_owned(), "iot, lan".to_owned())];

        // The WAN on it too isn't named.
        assert_eq!(
            shared(
                "      interfaces:
        lan: eth0
        iot: eth0
        wan: eth0"
            ),
            pair("eth0")
        );
        // One of a zone's interfaces, whichever zone lists more.
        assert_eq!(
            shared(
                "      interfaces:
        lan: [eth0, wlan0]
        iot: wlan0
        wan: eth1"
            ),
            pair("wlan0")
        );
        assert_eq!(
            shared(
                "      interfaces:
        lan: eth0
        iot: [eth0.10, eth0]
        wan: eth1"
            ),
            pair("eth0")
        );
    }

    #[test]
    fn no_zone_is_on_splots_mesh_interface() {
        for (zone, interfaces) in [
            ("iot", "lan: eth0, iot: spl_mesh, wan: eth1"),
            ("lan", "lan: [eth0, spl_mesh], iot: eth0.10, wan: eth1"),
            ("wan", "lan: eth0, iot: eth0.10, wan: spl_mesh"),
        ] {
            let r = on_linux("nftables", &format!("      interfaces: {{ {interfaces} }}"));
            assert!(
                error_at(
                    &r,
                    &format!("nodes.Home.platform.interfaces.{zone}"),
                    |e| matches!(e, ValidationError::MeshDeviceInZone { .. })
                ),
                "{zone}: {:?}",
                messages(&r)
            );
            assert_eq!(r.errors.len(), 1, "{zone}: {:?}", messages(&r));
        }
    }

    #[test]
    fn an_openwrt_node_has_no_interfaces() {
        // Its zones are fw4's, whether splot manages the firewall or not.
        for platform in [
            "      os: openwrt",
            "      os: openwrt\n      firewall: none",
        ] {
            let r = report(&home(&format!(
                "{platform}\n      interfaces:\n        wan: eth1"
            )));
            assert!(error_at(&r, "nodes.Home.platform.interfaces", |e| {
                matches!(e, ValidationError::InterfacesOnOpenWrt { .. })
            }));
            assert_eq!(r.errors.len(), 1, "{:?}", messages(&r));
        }
    }

    #[test]
    fn a_node_may_say_where_splot_reaches_it_over_ssh() {
        let ssh = |lines: &str| platform(lines).ssh().map(ToString::to_string);

        assert_eq!(
            ssh("      os: openwrt\n      ssh: root@192.168.1.1").as_deref(),
            Some("root@192.168.1.1")
        );
        assert_eq!(ssh("      os: openwrt"), None);

        let err = serde_norway::from_str::<Config>(&home(
            "      os: openwrt\n      ssh: -oProxyCommand=sh",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("starts with '-', which ssh would read as an option"),
            "{err}"
        );
    }

    #[test]
    fn a_node_whose_platform_fails_is_left_out() {
        let config = config(&home("      os: linux"));
        let mut report = ValidationReport::default();

        assert!(check_platforms(&config, &mut report).is_empty());
        assert_eq!(report.errors.len(), 4);
    }

    #[test]
    fn the_os_and_the_platform_are_required() {
        let parse = |yaml: &str| {
            serde_norway::from_str::<Config>(yaml)
                .map(|_| ())
                .unwrap_err()
                .to_string()
        };

        let err = parse(&home("      wireguard: netifd"));
        assert!(err.contains("missing field `os`"), "{err}");

        let err = parse(&home("      os: openwrt").replace("    platform:\n      os", "    os"));
        assert!(err.contains("unknown field `os`"), "{err}");
        let err = parse(&home("").replace("    platform:\n\n", ""));
        assert!(err.contains("missing field `platform`"), "{err}");

        let err = parse(&home("      os: debian"));
        assert!(err.contains("unknown variant `debian`"), "{err}");
        let err = parse(&home("      os: openwrt\n      dhcp: odhcpd"));
        assert!(
            err.contains("\"odhcpd\" isn't a dhcp program splot knows: dnsmasq, or none"),
            "{err}"
        );
        let err = parse(&home("      os: openwrt\n      routing: bird"));
        assert!(err.contains("unknown field `routing`"), "{err}");
    }
}
