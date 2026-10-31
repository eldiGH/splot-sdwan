//! DNS: each node's domain and the address it answers it at, and the names
//! splot puts into a domain where it manages that node's DNS.

use std::collections::{BTreeMap, HashMap};

use crate::{
    config::{Config, ServiceHost},
    model::{
        host::{Host, HostRef, Place},
        node::Node,
        platform::Platform,
        validator::types::{ValidationError, ValidationReport},
    },
    types::{
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, DnsLoc, HubClientLoc, HubLoc, NodeLoc,
            ServiceLoc, ZoneLoc,
        },
        dns::{DnsLabel, Hostname},
        identifier::Identifier,
    },
};

/// Where the config names `host`, whose address on its node is at `place`.
fn location(host: &HostRef, place: &Place) -> ConfigLocation {
    match (host, place) {
        (HostRef::Local { node, name }, Place::Zone { zone, .. }) => ConfigLocation::Node(
            node.clone(),
            NodeLoc::Zone(zone.clone(), ZoneLoc::Device(name.clone(), DeviceLoc::Root)),
        ),
        (HostRef::Local { node, name }, _) => ConfigLocation::Node(
            node.clone(),
            NodeLoc::Hub(HubLoc::Client(name.clone(), HubClientLoc::Root)),
        ),
        (HostRef::Client(name), _) => ConfigLocation::Client(name.clone(), ClientLoc::Root),
        (HostRef::Node(name), _) => ConfigLocation::Node(name.clone(), NodeLoc::Root),
    }
}

/// The names of one domain, case aside (DNS ignores it), and where each is.
#[derive(Default)]
struct Names(HashMap<String, ConfigLocation>);

impl Names {
    fn claim(&mut self, name: &Hostname, at: ConfigLocation, report: &mut ValidationReport) {
        let key = name.to_string().to_ascii_lowercase();
        match self.0.get(&key) {
            Some(with) => report.errors.push(ValidationError::DnsNameTaken {
                name: name.clone(),
                with: with.clone(),
                at,
            }),
            None => {
                self.0.insert(key, at);
            }
        }
    }
}

/// Each domain's address is on its node, no two domains overlap, and every
/// name splot puts into a domain is a host name that fits it, once.
pub(super) fn check_dns(
    config: &Config,
    platforms: &BTreeMap<Identifier, Platform>,
    nodes: &BTreeMap<Identifier, Node>,
    hosts: &[Host],
    report: &mut ValidationReport,
) {
    let mut domains: Vec<(&Identifier, &Hostname)> = Vec::new();
    for (name, node) in &config.nodes {
        let Some(dns) = &node.dns else { continue };
        let at = |loc| ConfigLocation::Node(name.clone(), NodeLoc::Dns(loc));

        if let Some(built) = nodes.get(name) {
            let on_node = built.mesh_address().ip() == dns.address
                || built
                    .zones()
                    .values()
                    .any(|zone| zone.network().contains(dns.address));
            if !on_node {
                report.errors.push(ValidationError::DnsAddressOffNode {
                    address: dns.address,
                    at: at(DnsLoc::Address),
                });
            }
        }

        if let Some((other, other_domain)) = domains
            .iter()
            .find(|(_, other)| dns.domain.is_within(other) || other.is_within(&dns.domain))
        {
            report.errors.push(ValidationError::DomainOverlap {
                domain: dns.domain.clone(),
                node: (*other).clone(),
                other: (*other_domain).clone(),
                at: at(DnsLoc::Domain),
            });
        }
        domains.push((name, &dns.domain));
    }

    // An endpoint name inside a domain goes to public DNS, the domain to its
    // node: the name can't be the domain itself.
    for (name, node) in &config.nodes {
        let Some(endpoint) = node.endpoint.as_ref().and_then(|endpoint| endpoint.name()) else {
            continue;
        };
        if let Some((owner, _)) = domains
            .iter()
            .find(|(_, domain)| endpoint.is_within(domain) && domain.is_within(endpoint))
        {
            report.errors.push(ValidationError::EndpointIsADomain {
                endpoint: endpoint.clone(),
                node: (*owner).clone(),
                at: ConfigLocation::Node(name.clone(), NodeLoc::Endpoint),
            });
        }
    }

    // The names in each domain splot serves: its node's hosts, and the names
    // their services ask for.
    let mut names: HashMap<&Identifier, Names> = HashMap::new();
    for (node, domain) in &domains {
        if platforms.get(*node).is_none_or(|p| p.dns().is_none()) {
            continue;
        }
        let names = names.entry(node).or_default();

        for host in hosts
            .iter()
            .filter(|host| !matches!(host.id(), HostRef::Node(_)))
        {
            let Some(place) = host
                .addresses()
                .iter()
                .map(|address| address.place())
                .find(|place| place.node() == Some(*node))
            else {
                continue;
            };
            let at = location(host.id(), place);
            match host
                .id()
                .name()
                .as_ref()
                .parse::<DnsLabel>()
                .and_then(|label| domain.with_label(label.as_ref()))
            {
                Ok(name) => names.claim(&name, at, report),
                Err(reason) => report.errors.push(ValidationError::InvalidDnsName {
                    name: host.id().name().to_string(),
                    node: (*node).clone(),
                    reason,
                    at,
                }),
            }
        }
    }

    for (service, host) in config.services() {
        if service.dns.is_empty() {
            continue;
        }
        let at = host.to_location(ServiceLoc::Dns);
        let node = match host {
            ServiceHost::Device { node_name, .. } | ServiceHost::HubClient { node_name, .. } => {
                node_name
            }
            ServiceHost::Node { .. } | ServiceHost::Client { .. } => {
                report
                    .errors
                    .push(ValidationError::DnsNameNotOnAHost { at });
                continue;
            }
        };
        let Some((_, domain)) = domains.iter().find(|(name, _)| *name == node) else {
            report.errors.push(ValidationError::DnsNameWithoutDomain {
                node: node.clone(),
                at,
            });
            continue;
        };

        for label in service.dns.iter() {
            match domain.with_label(label.as_ref()) {
                Ok(name) => {
                    if let Some(names) = names.get_mut(node) {
                        names.claim(&name, at.clone(), report);
                    }
                }
                Err(reason) => report.errors.push(ValidationError::InvalidDnsName {
                    name: label.to_string(),
                    node: node.clone(),
                    reason,
                    at: at.clone(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::{ValidationError, ValidationReport},
        test_support::{error_at, has_error, report},
    };

    /// Home and Cabin, their DHCP left alone, each with a device and lines of
    /// its own (`home`, `cabin`); Home a hub client, and Phone on Home's LAN,
    /// with lines of its own (`phone`).
    fn mesh(home: &str, cabin: &str, phone: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform: {{ os: openwrt, dhcp: none }}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: wg.home.example.org
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.16
            services:
              ipp: {{ port: 631, proto: tcp, allowFrom: Phone, dns: print }}
    hub:
      network: 10.100.10.0/24
      clients:
        camera: {{ publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=, ip: 10.100.10.2 }}
{home}
  Cabin:
    platform: {{ os: openwrt, dhcp: none }}
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas: {{ ip: 192.168.2.20 }}
{cabin}
clients:
  Phone:
    ips: {{ Home: {{ lan: 192.168.1.50 }} }}
{phone}
"
        )
    }

    const HOME: &str = "    dns: { domain: home.example.org, address: 192.168.1.53 }";
    const CABIN: &str = "    dns: { domain: cabin.example.org, address: 10.100.0.2 }";

    fn messages(r: &ValidationReport) -> Vec<String> {
        r.errors.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn domains_on_their_nodes_and_names_that_fit_them_pass() {
        // Home's address a role address on its LAN; Cabin's its mesh IP.
        let r = report(&mesh(HOME, CABIN, ""));
        assert!(r.errors.is_empty(), "{:?}", messages(&r));
    }

    #[test]
    fn a_dns_address_is_on_its_node() {
        let r = report(&mesh(
            &HOME.replace("192.168.1.53", "192.168.2.53"),
            CABIN,
            "",
        ));
        assert!(error_at(&r, "nodes.Home.dns.address", |e| matches!(
            e,
            ValidationError::DnsAddressOffNode { .. }
        )));
        assert!(!has_error(&r, |e| e.path().to_string() == "nodes.Cabin.dns.address"));
    }

    #[test]
    fn no_domain_overlaps_another_whichever_comes_first() {
        let overlap = |home: &str, cabin: &str| {
            let r = report(&mesh(
                &HOME.replace("home.example.org", home),
                &CABIN.replace("cabin.example.org", cabin),
                "",
            ));
            // Cabin comes first: the error is Home's.
            error_at(
                &r,
                "nodes.Home.dns.domain",
                |e| matches!(e, ValidationError::DomainOverlap { node, .. } if node.as_ref() == "Cabin"),
            )
        };

        assert!(overlap("example.org", "Example.org"));
        assert!(overlap("home.example.org", "example.org"));
        assert!(overlap("example.org", "cabin.example.org"));
        assert!(!overlap("home.example.org", "cabin.example.org"));
        assert!(!overlap("myexample.org", "example.org"));
    }

    #[test]
    fn a_name_splots_dns_serves_is_a_host_name() {
        let invalid = |r: &ValidationReport, at: &str| {
            error_at(r, at, |e| {
                matches!(e, ValidationError::InvalidDnsName { .. })
            })
        };
        let renamed = |from: &str, to: &str| report(&mesh(HOME, CABIN, "").replace(from, to));

        let r = renamed("printer:\n", "my_printer:\n");
        assert!(
            invalid(&r, "nodes.Home.zones.lan.devices.my_printer"),
            "{:?}",
            messages(&r)
        );
        let r = renamed("camera: {", "cam_1: {");
        assert!(
            invalid(&r, "nodes.Home.hub.clients.cam_1"),
            "{:?}",
            messages(&r)
        );
        let r = report(
            &mesh(HOME, CABIN, "")
                .replace("  Phone:\n", "  Phone_2:\n")
                .replace("allowFrom: Phone,", "allowFrom: Phone_2,"),
        );
        assert!(invalid(&r, "clients.Phone_2"), "{:?}", messages(&r));

        // splot's DNS left alone on Home, or Home without a domain: it names
        // nothing there.
        let r = report(
            &mesh(HOME, CABIN, "")
                .replace("printer:\n", "my_printer:\n")
                .replacen("dhcp: none }", "dhcp: none, dns: none }", 1),
        );
        assert!(r.errors.is_empty(), "{:?}", messages(&r));
        let r = report(
            &mesh("", CABIN, "")
                .replace("printer:\n", "my_printer:\n")
                .replace(", dns: print", ""),
        );
        assert!(r.errors.is_empty(), "{:?}", messages(&r));
    }

    #[test]
    fn a_name_is_once_in_its_domain_case_aside() {
        let taken = |r: &ValidationReport, at: &str, with: &str| {
            error_at(
                r,
                at,
                |e| matches!(e, ValidationError::DnsNameTaken { with: w, .. } if w.to_string() == with),
            )
        };
        // Phone and a device named after it: the device comes first.
        let r = report(&mesh(HOME, CABIN, "").replace("printer:\n", "PHONE:\n"));
        assert!(
            taken(&r, "clients.Phone", "nodes.Home.zones.lan.devices.PHONE"),
            "{:?}",
            messages(&r)
        );
        // A service's name: after the hosts, whichever sorts first.
        for name in ["camera", "zz", "Camera"] {
            let r = report(
                &mesh(HOME, CABIN, "").replace("dns: print", &format!("dns: [print, {name}]")),
            );
            let expected = name.eq_ignore_ascii_case("camera");
            assert_eq!(
                taken(
                    &r,
                    "nodes.Home.zones.lan.devices.printer.services.ipp.dns",
                    "nodes.Home.hub.clients.camera"
                ),
                expected,
                "{name}: {:?}",
                messages(&r)
            );
        }
        // The node itself has no name in its domain.
        let r = report(&mesh(HOME, CABIN, "").replace("printer:\n", "home:\n"));
        assert!(r.errors.is_empty(), "{:?}", messages(&r));
        // The same name in another domain is another name.
        let r = report(
            &mesh(HOME, CABIN, "")
                .replace("nas: { ip: 192.168.2.20 }", "printer: { ip: 192.168.2.20 }"),
        );
        assert!(r.errors.is_empty(), "{:?}", messages(&r));
    }

    #[test]
    fn only_a_devices_or_a_hub_clients_service_gets_a_name_in_a_domain_its_node_has() {
        let not_on_a_host = |r: &ValidationReport, at: &str| {
            error_at(r, at, |e| {
                matches!(e, ValidationError::DnsNameNotOnAHost { .. })
            })
        };
        let home = format!(
            "{HOME}\n    services:\n      ssh: {{ port: 22, proto: tcp, allowFrom: Phone, dns: router }}"
        );
        let phone =
            "    services:\n      web: { port: 80, proto: tcp, allowFrom: Home, dns: phone-web }";
        let r = report(&mesh(&home, CABIN, phone));
        assert!(
            not_on_a_host(&r, "nodes.Home.services.ssh.dns"),
            "{:?}",
            messages(&r)
        );
        assert!(
            not_on_a_host(&r, "clients.Phone.services.web.dns"),
            "{:?}",
            messages(&r)
        );

        let r = report(&mesh(
            HOME,
            "",
            "",
        ).replace("nas: { ip: 192.168.2.20 }", "nas: { ip: 192.168.2.20, services: { smb: { port: 445, proto: tcp, allowFrom: Phone, dns: files } } }"));
        assert!(
            error_at(
                &r,
                "nodes.Cabin.zones.lan.devices.nas.services.smb.dns",
                |e| {
                    matches!(e, ValidationError::DnsNameWithoutDomain { node, .. } if node.as_ref() == "Cabin")
                }
            ),
            "{:?}",
            messages(&r)
        );
    }

    #[test]
    fn an_endpoint_name_is_inside_a_domain_not_the_domain_itself() {
        let r = report(
            &mesh(HOME, CABIN, "").replace("endpoint: 5.6.7.8", "endpoint: cabin.example.org"),
        );
        assert!(
            error_at(&r, "nodes.Cabin.endpoint", |e| {
                matches!(e, ValidationError::EndpointIsADomain { node, .. } if node.as_ref() == "Cabin")
            }),
            "{:?}",
            messages(&r)
        );
        // Home's is inside its domain: fine.
        assert!(!has_error(&r, |e| e.path().to_string() == "nodes.Home.endpoint"));
    }
}
