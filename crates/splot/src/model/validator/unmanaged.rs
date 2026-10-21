//! Concerns left alone: what a node won't carry out because its platform leaves
//! a concern to the operator (`none`), and what's theirs to do instead.

use std::collections::BTreeMap;

use crate::{
    model::{
        host::{Host, HostAddress, HostRef, Place},
        platform::Platform,
        service::Service,
        validator::types::{ValidationReport, ValidationWarning},
    },
    types::{
        config_location::{ConfigLocation, NodeLoc, PlatformLoc},
        identifier::Identifier,
        platform::Concern,
    },
};

/// One warning per node and concern left alone, when the config asks that node
/// for something there. A concern left alone with nothing asked of it is no
/// warning: the config says so already.
pub(super) fn check_unmanaged(
    platforms: &BTreeMap<Identifier, Platform>,
    hosts: &[Host],
    services: &BTreeMap<HostRef, BTreeMap<Identifier, Service>>,
    report: &mut ValidationReport,
) {
    let services_of = |host: &Host| services.get(host.id()).into_iter().flatten();
    let at = |node: &Identifier, concern| {
        ConfigLocation::Node(
            node.clone(),
            NodeLoc::Platform(PlatformLoc::Concern(concern)),
        )
    };

    for (node, platform) in platforms {
        // What the node forwards from its WAN, to which address.
        let forwarded: Vec<(String, &Place)> = hosts
            .iter()
            .flat_map(|host| {
                services_of(host).filter_map(move |(name, service)| {
                    let target = service.wan()?.target(node)?;
                    Some((format!("{}.{name}", host.id()), target.place()))
                })
            })
            .collect();

        if platform.firewall().is_none() {
            // What the node's firewall would let in: its ingress rules, from the
            // sources whose traffic crosses it (not one on the same link as the
            // host).
            let unenforced: Vec<String> = hosts
                .iter()
                .flat_map(|host| {
                    let addresses: Vec<&HostAddress> = host.addresses_on(|on| on == node).collect();
                    services_of(host)
                        .filter(move |(_, service)| {
                            service.sources().on(node).any(|source| {
                                addresses
                                    .iter()
                                    .any(|address| !address.shares_link(source.network().ip()))
                            })
                        })
                        .map(|(name, _)| format!("{}.{name}", host.id()))
                })
                .collect();
            let unforwarded: Vec<String> = forwarded
                .iter()
                .map(|(service, _)| service.clone())
                .collect();
            let mesh_interface = platform.wireguard().is_some();

            if !unenforced.is_empty() || !unforwarded.is_empty() || mesh_interface {
                report.warnings.push(ValidationWarning::FirewallLeftAlone {
                    node: node.clone(),
                    unenforced,
                    unforwarded,
                    mesh_interface,
                    at: at(node, Concern::Firewall),
                });
            }
        }

        if platform.wireguard().is_none() && platform.firewall().is_some() {
            // A forward to a host reached over the mesh would name the mesh zone.
            let unforwarded = forwarded
                .iter()
                .filter(|(_, place)| !matches!(place, Place::Zone { .. }))
                .map(|(service, _)| service.clone())
                .collect();

            report.warnings.push(ValidationWarning::WireGuardLeftAlone {
                node: node.clone(),
                unforwarded,
                at: at(node, Concern::WireGuard),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::ValidationWarning,
        test_support::{report, warning_at},
    };

    // Home: ssh on the router, from Phone; the printer on its lan, from Phone and
    // forwarded from the WAN; the camera on its hub, forwarded too. Phone's own
    // http is forwarded to its mesh IP. Cabin's ssh is no concern of Home's.
    fn mesh(home_platform: &str) -> String {
        mesh_without_hub(home_platform).replace(
            "    wanZone: wan\n",
            "    wanZone: wan
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, wan: { via: Home } }
",
        )
    }

    /// The same, without Home's hub: a node whose WireGuard splot leaves alone
    /// has none.
    fn mesh_without_hub(home_platform: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
{home_platform}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      ssh: {{ port: 22, proto: tcp, allowFrom: Phone }}
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
            services:
              ipp: {{ port: 631, proto: tcp, allowFrom: Phone, wan: {{ via: Home }} }}
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    services:
      ssh: {{ port: 22, proto: tcp, allowFrom: Phone }}
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
    services:
      http: {{ port: 8080, proto: tcp, wan: {{ via: Home }} }}
"
        )
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    fn messages(warnings: &[ValidationWarning]) -> Vec<String> {
        warnings.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_firewall_left_alone_names_what_it_wont_do() {
        let r = report(&mesh("      firewall: none"));

        assert!(warning_at(
            &r,
            "nodes.Home.platform.firewall",
            |w| matches!(
                w,
                ValidationWarning::FirewallLeftAlone { unenforced, unforwarded, mesh_interface: true, .. }
                    if *unenforced == strings(&["Home.ssh", "Home.printer.ipp"])
                        && *unforwarded == strings(&["Home.printer.ipp", "Home.camera.rtsp", "Phone.http"])
            )
        ));
        assert_eq!(
            messages(&r.warnings),
            [
                "nodes.Home.platform.firewall: splot leaves Home's firewall alone - allowFrom isn't enforced there, your own rules decide who reaches Home.ssh, Home.printer.ipp; nothing is forwarded from its WAN to Home.printer.ipp, Home.camera.rtsp, Phone.http; put splot's mesh interface into a zone of yours, and let its listen port in from the WAN"
            ]
        );
    }

    #[test]
    fn a_firewall_left_alone_with_the_wireguard_has_no_mesh_interface_to_place() {
        let r = report(&mesh_without_hub(
            "      firewall: none\n      wireguard: none",
        ));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.firewall",
            |w| matches!(
                w,
                ValidationWarning::FirewallLeftAlone {
                    mesh_interface: false,
                    ..
                }
            )
        ));
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn a_concern_left_alone_with_nothing_asked_of_it_says_nothing() {
        // Home's printer is reached only from its own lan (the same link: no
        // firewall sees it), and only Cabin forwards anything: nothing for
        // Home's firewall to do.
        let r = report(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
      firewall: none
      wireguard: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
            services:
              ipp: { port: 631, proto: tcp, allowFrom: Home.lan }
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
    services:
      http: { port: 8080, proto: tcp, wan: { via: Cabin } }
",
        );

        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(r.warnings.is_empty(), "{:?}", messages(&r.warnings));
    }

    #[test]
    fn wireguard_left_alone_leaves_the_firewall_without_a_mesh_zone() {
        // The printer is on Home's own lan: its forward stays.
        let r = report(&mesh_without_hub("      wireguard: none"));
        assert!(r.errors.is_empty(), "{:?}", r.errors);

        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unforwarded, .. }
                    if *unforwarded == strings(&["Phone.http"])
            )
        ));
        assert_eq!(
            messages(&r.warnings),
            [
                "nodes.Home.platform.wireguard: splot leaves Home's WireGuard alone, so its firewall has no mesh zone - mesh traffic arrives in your interface's zone, under your rules; nothing is forwarded from its WAN to what's reached over the mesh: Phone.http"
            ]
        );
    }

    #[test]
    fn concerns_splot_manages_and_dhcp_or_dns_left_alone_say_nothing() {
        assert!(report(&mesh("")).warnings.is_empty());
        // Nothing undone yet: the addresses are facts the config states, and
        // splot generates no DNS config.
        let r = report(&mesh("      dhcp: none\n      dns: none"));
        assert!(r.warnings.is_empty(), "{:?}", messages(&r.warnings));
    }
}
