//! Platforms: which software runs each node, and which concerns splot manages
//! there.

use std::collections::BTreeMap;

use crate::{
    config::{self, Config},
    consts,
    model::{
        platform::Platform,
        validator::types::{ValidationError, ValidationReport},
    },
    types::{
        config_location::{ConfigLocation, HubLoc, NodeLoc, PlatformLoc},
        identifier::Identifier,
        platform::{Os, Program, Setting, names},
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

            Some((name.clone(), platform))
        })
        .collect()
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
