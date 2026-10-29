//! Concerns left alone: what a node won't carry out because its platform leaves
//! a concern to the operator (`none`), and what's theirs to do instead.

use std::collections::BTreeMap;

use crate::{
    model::{
        host::{Host, HostAddress, HostRef, Place},
        node::Node,
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
    nodes: &BTreeMap<Identifier, Node>,
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
        // Others dial it: its listen port needs letting in.
        let dialled = nodes
            .get(node)
            .is_some_and(|node| node.endpoint().is_some());
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
            // host). And every service at a global client's mesh IP: each node is
            // the only gate between what's behind it and the client.
            let unenforced: Vec<String> = hosts
                .iter()
                .flat_map(|host| {
                    let addresses: Vec<&HostAddress> =
                        host.addresses_on(|on| on == Some(node)).collect();
                    let roaming = host.addresses_on(|on| on.is_none()).next().is_some();
                    services_of(host)
                        .filter(move |(_, service)| {
                            (roaming && !service.sources().is_empty())
                                || service.sources().on(node).any(|source| {
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
                    listen_port: mesh_interface && dialled,
                    at: at(node, Concern::Firewall),
                });
            }
        }

        if platform.wireguard().is_none() && platform.firewall().is_some() {
            // What crosses the mesh gets no rule: to a host on the node from a
            // source outside its zones, or from its zones to a host elsewhere.
            // What its zones send a global client's mesh IP goes into the
            // operator's interface zone, past splot's deny too.
            let unenforced = hosts
                .iter()
                .flat_map(|host| {
                    let here = host.addresses_on(|on| on == Some(node)).next().is_some();
                    let elsewhere = host.addresses_on(|on| on != Some(node)).next().is_some();
                    let roaming = host.addresses_on(|on| on.is_none()).next().is_some();
                    services_of(host)
                        .filter(move |(_, service)| {
                            (roaming && !service.sources().is_empty())
                                || service.sources().on(node).any(|source| {
                                    let behind = source.place().zone_on(node).is_some();
                                    (here && !behind) || (elsewhere && behind)
                                })
                        })
                        .map(|(name, _)| format!("{}.{name}", host.id()))
                })
                .collect();
            // A forward to a host reached over the mesh would name the mesh zone.
            let unforwarded = forwarded
                .iter()
                .filter(|(_, place)| place.zone_on(node).is_none())
                .map(|(service, _)| service.clone())
                .collect();

            report.warnings.push(ValidationWarning::WireGuardLeftAlone {
                node: node.clone(),
                unenforced,
                unforwarded,
                listen_port: dialled,
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
    // http is forwarded to its mesh IP. Cabin's ssh, from Phone and Home's lan,
    // is Home's concern only on its way out.
    fn mesh(home_platform: &str) -> String {
        mesh_without_hub(home_platform).replacen(
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
            1,
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
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    services:
      ssh: {{ port: 22, proto: tcp, allowFrom: [Phone, Home.lan] }}
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
                ValidationWarning::FirewallLeftAlone { unenforced, unforwarded, mesh_interface: true, listen_port: true, .. }
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

    /// Phone's http, let in from Cabin itself: from nothing behind Home.
    fn with_phone_http_from_cabin(yaml: &str) -> String {
        yaml.replace(
            "http: { port: 8080, proto: tcp, wan: { via: Home } }",
            "http: { port: 8080, proto: tcp, allowFrom: Cabin.$node, wan: { via: Home } }",
        )
    }

    #[test]
    fn a_firewall_left_alone_leaves_a_global_clients_mesh_ip_open_from_behind_it() {
        // Phone is a peer on every node, so Home is the only gate between what's
        // behind it and Phone's mesh IP: without Home's deny, its lan reaches
        // Phone as your rules let it, though allowFrom names nothing there.
        let r = report(&with_phone_http_from_cabin(&mesh("      firewall: none")));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.firewall",
            |w| matches!(
                w,
                ValidationWarning::FirewallLeftAlone { unenforced, .. }
                    if *unenforced == strings(&["Home.ssh", "Home.printer.ipp", "Phone.http"])
            )
        ));
    }

    #[test]
    fn a_firewall_left_alone_on_a_node_nobody_dials_has_no_listen_port_to_let_in() {
        let r = report(
            &mesh_without_hub("      firewall: none").replace("    endpoint: 1.2.3.4\n", ""),
        );
        assert!(r.errors.is_empty(), "{:?}", r.errors);

        assert!(warning_at(
            &r,
            "nodes.Home.platform.firewall",
            |w| matches!(
                w,
                ValidationWarning::FirewallLeftAlone {
                    mesh_interface: true,
                    listen_port: false,
                    ..
                }
            )
        ));
        assert!(
            messages(&r.warnings)[0].ends_with("; put splot's mesh interface into a zone of yours"),
            "{:?}",
            messages(&r.warnings)
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
                    listen_port: false,
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
        // The printer is on Home's own lan: its forward stays. What crosses the
        // mesh gets no rule: from Phone to Home's ssh and printer, and from Home's
        // lan out to Cabin's ssh.
        let r = report(&mesh_without_hub("      wireguard: none"));
        assert!(r.errors.is_empty(), "{:?}", r.errors);

        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unenforced, unforwarded, listen_port: true, .. }
                    if *unenforced == strings(&["Cabin.ssh", "Home.ssh", "Home.printer.ipp"])
                        && *unforwarded == strings(&["Phone.http"])
            )
        ));
        assert_eq!(
            messages(&r.warnings),
            [
                "nodes.Home.platform.wireguard: splot leaves Home's WireGuard alone, so its firewall has no mesh zone - mesh traffic arrives in your interface's zone, under your rules, and your rule lets its listen port in from the WAN; allowFrom isn't enforced for what crosses the mesh to Cabin.ssh, Home.ssh, Home.printer.ipp; nothing is forwarded from its WAN to what's reached over the mesh: Phone.http"
            ]
        );
    }

    #[test]
    fn wireguard_left_alone_leaves_a_global_clients_mesh_ip_open_from_behind_it() {
        // What Home's lan sends Phone goes into your interface's zone, which
        // splot's deny doesn't cover.
        let r = report(&with_phone_http_from_cabin(&mesh_without_hub(
            "      wireguard: none",
        )));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unenforced, .. }
                    if *unenforced == strings(&["Cabin.ssh", "Home.ssh", "Home.printer.ipp", "Phone.http"])
            )
        ));
    }

    #[test]
    fn wireguard_left_alone_enforces_what_stays_at_the_site() {
        // The printer from Home's own lan: no mesh in between.
        let yaml = mesh_without_hub("      wireguard: none").replace(
            "allowFrom: Phone, wan: { via: Home }",
            "allowFrom: Home.lan, wan: { via: Home }",
        );
        let r = report(&yaml);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unenforced, .. }
                    if *unenforced == strings(&["Cabin.ssh", "Home.ssh"])
            )
        ));
    }

    #[test]
    fn a_firewall_left_alone_would_not_see_the_nodes_own_traffic() {
        // What Home sends leaves through its output: `$node` and Home itself
        // leave nothing to Home's firewall. Cabin itself comes in over the mesh.
        let yaml = mesh_without_hub("      firewall: none")
            .replace(
                "ssh: { port: 22, proto: tcp, allowFrom: Phone }",
                "ssh: { port: 22, proto: tcp, allowFrom: [$node, Home.$node] }",
            )
            .replace(
                "allowFrom: Phone, wan: { via: Home }",
                "allowFrom: Cabin.$node, wan: { via: Home }",
            );
        let r = report(&yaml);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.firewall",
            |w| matches!(
                w,
                ValidationWarning::FirewallLeftAlone { unenforced, .. }
                    if *unenforced == strings(&["Home.printer.ipp"])
            )
        ));
    }

    #[test]
    fn wireguard_left_alone_leaves_only_other_nodes_themselves_unenforced() {
        // Home itself, toward Cabin's ssh, leaves through Home's output; Cabin
        // itself, toward Home's ssh, crosses the mesh.
        let yaml = mesh_without_hub("      wireguard: none")
            .replace(
                "ssh: { port: 22, proto: tcp, allowFrom: Phone }",
                "ssh: { port: 22, proto: tcp, allowFrom: Cabin.$node }",
            )
            .replace("allowFrom: [Phone, Home.lan]", "allowFrom: Home.$node");
        let r = report(&yaml);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unenforced, .. }
                    if *unenforced == strings(&["Home.ssh", "Home.printer.ipp"])
            )
        ));
    }

    #[test]
    fn wireguard_left_alone_forwards_nothing_to_another_nodes_zone() {
        // Home reaches Cabin's nas over the mesh, though both have a lan.
        let yaml = mesh_without_hub("      wireguard: none").replace(
            "    meshIp: 10.100.0.2\n",
            "    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas:
            ip: 192.168.2.20
            macs: AA:BB:CC:DD:EE:02
            services:
              https: { port: 443, proto: tcp, wan: { via: Home } }
",
        );
        let r = report(&yaml);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone { unforwarded, .. }
                    if *unforwarded == strings(&["Cabin.nas.https", "Phone.http"])
            )
        ));
    }

    #[test]
    fn wireguard_left_alone_on_a_node_nobody_dials_has_no_listen_port_to_let_in() {
        let r = report(
            &mesh_without_hub("      wireguard: none").replace("    endpoint: 1.2.3.4\n", ""),
        );
        assert!(r.errors.is_empty(), "{:?}", r.errors);

        assert!(warning_at(
            &r,
            "nodes.Home.platform.wireguard",
            |w| matches!(
                w,
                ValidationWarning::WireGuardLeftAlone {
                    listen_port: false,
                    ..
                }
            )
        ));
        assert!(
            !messages(&r.warnings)[0].contains("listen port"),
            "{:?}",
            messages(&r.warnings)
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
