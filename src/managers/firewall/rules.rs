use std::{collections::HashMap, fmt, net::Ipv4Addr};

use crate::{
    config::{Config, Service, ZoneOrVpnInterface},
    managers::{
        UciSectionBuilder,
        firewall::{
            consts::FIREWALL_FILE_NAME,
            types::{FirewallAction, TagResolution},
        },
    },
    naming,
    protocol::Protocols,
    types::{
        allow_from_ref::AllowFromRef,
        identifier::Identifier,
        ip::{Ipv4Interface, Ipv4Network},
        port::PortOrRange,
    },
    uci::UciBatchCommand,
};

pub struct FirewallRule {
    pub name: String,
    pub src_ip: Vec<Ipv4Network>,
    pub proto: Protocols,
    pub dest_port: PortOrRange,
    pub dest_ip: Vec<Ipv4Network>,
    pub target: FirewallAction,
}

impl FirewallRule {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "rule")
            .set("name", naming::name_prefixed(&self.name))
            .set("src", "*")
            .set("dest", "*")
            .set("dest_port", self.dest_port.to_string())
            .set("target", self.target.to_string())
            .extend_list("dest_ip", self.dest_ip.iter())
            .extend_list("src_ip", self.src_ip.iter())
            .extend_list("proto", self.proto.iter())
            .build()
    }
}

fn generate_rule_from_service(
    service_name: &Identifier,
    service: &Service,
    dest_addresses: impl IntoIterator<Item = Ipv4Interface>,
    owner_name: impl fmt::Display,
    tag_resolutions: &HashMap<AllowFromRef, TagResolution>,
    src_ip_filter: Option<&[Ipv4Network]>,
) -> Option<FirewallRule> {
    let dest_addresses: Vec<Ipv4Interface> = dest_addresses.into_iter().collect();

    let src_ips: Vec<Ipv4Network> = service
        .allow_from
        .iter()
        .flat_map(|tag| {
            tag_resolutions
                .get(tag)
                .expect("allowFrom tag not found in resolution map")
                .values()
                .flatten()
                // skip same-LAN sources — they don't traverse this router's firewall
                .filter(|resolution| {
                    dest_addresses
                        .iter()
                        .any(|dest_address| !dest_address.is_in_same_network(resolution.ip()))
                })
        })
        .filter(|network| {
            let Some(src_ip_filter) = src_ip_filter else {
                return true;
            };

            src_ip_filter
                .iter()
                .any(|address| address.contains(network.ip()))
        })
        .cloned()
        .collect();

    if src_ips.is_empty() {
        return None;
    }

    let rule_name = format!("{}_{}", owner_name, service_name);

    Some(FirewallRule {
        src_ip: src_ips,
        name: rule_name,
        dest_ip: dest_addresses
            .iter()
            .map(|address| Ipv4Network::host(address.ip()))
            .collect(),
        dest_port: service.port.internal(),
        proto: service.proto.clone().into(),
        target: FirewallAction::Accept,
    })
}

fn client_address_on_network(ip: Ipv4Addr, network: ZoneOrVpnInterface<'_>) -> Ipv4Interface {
    match network {
        ZoneOrVpnInterface::VpnInterface(_) => Ipv4Interface::host(ip),
        ZoneOrVpnInterface::Zone(zone) => Ipv4Interface::from_ip(ip, zone.address.prefix())
            .expect("ip and prefix should be validated at this point."),
    }
}

pub fn get_firewall_ingress_rules(
    config: &Config,
    own_name: &Identifier,
    tags: &HashMap<AllowFromRef, TagResolution>,
) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = Vec::new();

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    for (service_name, service) in &node.services {
        rules.extend(generate_rule_from_service(
            service_name,
            service,
            node.host_interfaces(),
            own_name,
            tags,
            None,
        ));
    }

    for zone in node.zones.values() {
        for (device_name, device) in &zone.devices {
            for (service_name, service) in &device.services {
                rules.extend(generate_rule_from_service(
                    service_name,
                    service,
                    [Ipv4Interface::from_ip(device.ip, zone.address.prefix())
                        .expect("ip and prefix should already be validated")],
                    device_name,
                    tags,
                    None,
                ));
            }
        }
    }

    for vpn_interface in node.vpn_interfaces.values() {
        for (client_name, client) in &vpn_interface.clients {
            for (service_name, service) in &client.services {
                // /32 dest: VPN interfaces are routed, not L2-bridged — peers on the same
                // interface traverse the firewall, so the same-network filter must keep
                // same-subnet sources rather than treating them as no-ops.
                rules.extend(generate_rule_from_service(
                    service_name,
                    service,
                    [Ipv4Interface::host(client.ip)],
                    client_name,
                    tags,
                    None,
                ));
            }
        }
    }

    for (client_name, client) in &config.clients {
        let Some(networks) = client.ips.get(own_name) else {
            continue;
        };

        let ips: Vec<Ipv4Interface> = networks
            .iter()
            .filter_map(|(network_name, ip)| {
                let network = node.network_by_name(network_name)?;

                Some(client_address_on_network(*ip, network))
            })
            .collect();

        for (service_name, service) in &client.services {
            rules.extend(generate_rule_from_service(
                service_name,
                service,
                ips.iter().cloned(),
                client_name,
                tags,
                None,
            ));
        }
    }

    rules
}

pub fn get_firewall_egress_rules(
    config: &Config,
    own_name: &Identifier,
    tags: &HashMap<AllowFromRef, TagResolution>,
) -> Vec<FirewallRule> {
    let mut rules = Vec::new();

    let local_networks: Vec<Ipv4Network> = config
        .nodes
        .get(own_name)
        .expect("own node not found - should be validated before running manager")
        .networks()
        .collect();

    for (node_name, node) in &config.nodes {
        if node_name == own_name {
            continue;
        }

        let host_interfaces: Vec<Ipv4Interface> = node.host_interfaces().collect();

        rules.extend(node.services.iter().filter_map(|(service_name, service)| {
            generate_rule_from_service(
                service_name,
                service,
                host_interfaces.iter().cloned(),
                node_name,
                tags,
                Some(&local_networks),
            )
        }));

        let with_node_prefix = |owner_name: &Identifier| format!("{node_name}_{owner_name}");

        for zone in node.zones.values() {
            for (device_name, device) in &zone.devices {
                for (service_name, service) in &device.services {
                    rules.extend(generate_rule_from_service(
                        service_name,
                        service,
                        [Ipv4Interface::from_ip(device.ip, zone.address.prefix())
                            .expect("ip and prefix should already be validated")],
                        with_node_prefix(device_name),
                        tags,
                        Some(&local_networks),
                    ))
                }
            }
        }

        for vpn_interface in node.vpn_interfaces.values() {
            for (client_name, client) in &vpn_interface.clients {
                for (service_name, service) in &client.services {
                    // /32 dest: VPN interfaces are routed, not L2-bridged — peers on the same
                    // interface traverse the firewall, so the same-network filter must keep
                    // same-subnet sources rather than treating them as no-ops.
                    rules.extend(generate_rule_from_service(
                        service_name,
                        service,
                        [Ipv4Interface::host(client.ip)],
                        with_node_prefix(client_name),
                        tags,
                        Some(&local_networks),
                    ))
                }
            }
        }
    }

    for (client_name, client) in &config.clients {
        let external_client_addresses: Vec<Ipv4Interface> = client
            .ips
            .iter()
            .filter_map(|(node_name, networks)| {
                if node_name == own_name {
                    return None;
                }
                let node = config.nodes.get(node_name)?;

                Some(networks.iter().filter_map(|(network_name, ip)| {
                    let network = node.network_by_name(network_name)?;

                    Some(client_address_on_network(*ip, network))
                }))
            })
            .flatten()
            .collect();

        for (service_name, service) in &client.services {
            rules.extend(generate_rule_from_service(
                service_name,
                service,
                external_client_addresses.iter().cloned(),
                client_name,
                tags,
                Some(&local_networks),
            ))
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        managers::firewall::tag_resolution::build_tags_resolution_map, test_support::config,
    };

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn ingress(yaml: &str, own: &str) -> Vec<FirewallRule> {
        let cfg = config(yaml);
        let tags = build_tags_resolution_map(&cfg, &id(own));
        get_firewall_ingress_rules(&cfg, &id(own), &tags)
    }

    #[test]
    fn allowfrom_produces_ingress_rule() {
        // Home node service ssh with allowFrom: Phone → rule with Phone's meshIp in src_ip.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: Phone
clients:
  Phone:
    publicKey: BBBB
    meshIp: 10.100.0.100
",
            "Home",
        );
        let rule = rules
            .iter()
            .find(|r| r.name.contains("ssh"))
            .expect("ssh rule missing");
        assert!(
            rule.src_ip
                .iter()
                .any(|n| n.to_string() == "10.100.0.100/32"),
            "Phone mesh IP missing from src_ip"
        );
    }

    #[test]
    fn same_lan_source_filtered_out() {
        // LanClient is in the same /24 as printer → source filtered → no rule produced.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
            services:
              print:
                port: 9100
                proto: tcp
                allowFrom: LanClient
clients:
  LanClient:
    ips:
      Home:
        lan: 192.168.1.60
",
            "Home",
        );
        assert!(
            !rules.iter().any(|r| r.name.contains("print")),
            "same-LAN source should not produce a rule"
        );
    }

    #[test]
    fn no_allowfrom_no_ingress_rule() {
        // wan-only service — no allowFrom means no ingress firewall rule needed.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
            "Home",
        );
        assert!(rules.is_empty());
    }

    #[test]
    fn cross_node_client_resolved_via_mesh_ip() {
        // Phone lives on Cabin's lan but is reachable from Home via its meshIp.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: Phone
  Cabin:
    publicKey: CCCC
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
clients:
  Phone:
    publicKey: BBBB
    meshIp: 10.100.0.100
",
            "Home",
        );
        let rule = rules.iter().find(|r| r.name.contains("ssh")).unwrap();
        assert!(
            rule.src_ip
                .iter()
                .any(|n| n.to_string() == "10.100.0.100/32")
        );
    }

    fn egress(yaml: &str, own: &str) -> Vec<FirewallRule> {
        let cfg = config(yaml);
        let tags = build_tags_resolution_map(&cfg, &id(own));
        get_firewall_egress_rules(&cfg, &id(own), &tags)
    }

    // Home-local workstation (tag `staff`) wants to reach Cabin's `web` service.
    // From Home's perspective this is egress: Home must ACCEPT the local source
    // toward the remote (mesh-reachable) destination.
    const EGRESS_FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          workstation:
            ip: 192.168.1.10
            macs: AA:BB:CC:DD:EE:01
            tags: staff
  Cabin:
    publicKey: CCCC
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
    services:
      web:
        port: 80
        proto: tcp
        allowFrom: staff
";

    #[test]
    fn egress_rule_for_remote_service_from_local_source() {
        let rules = egress(EGRESS_FIXTURE, "Home");
        let rule = rules
            .iter()
            .find(|r| r.name.contains("web"))
            .expect("egress rule for Cabin web missing");
        // src is the Home-local workstation; dest includes Cabin's mesh host IP.
        assert!(
            rule.src_ip
                .iter()
                .any(|n| n.to_string() == "192.168.1.10/32"),
            "local source workstation missing from src_ip"
        );
        assert!(
            rule.dest_ip
                .iter()
                .any(|n| n.to_string() == "10.100.0.2/32"),
            "Cabin mesh host IP missing from dest_ip"
        );
    }

    #[test]
    fn egress_filters_non_local_sources() {
        // Cabin's `web` is allowed from a Cabin-local device. From Home's perspective
        // that source is not local, so Home emits no egress rule for it.
        let rules = egress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCC
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          cabinpc:
            ip: 192.168.2.10
            macs: AA:BB:CC:DD:EE:02
            tags: locals
    services:
      web:
        port: 80
        proto: tcp
        allowFrom: locals
",
            "Home",
        );
        assert!(
            !rules.iter().any(|r| r.name.contains("web")),
            "non-local source should not produce an egress rule on Home"
        );
    }

    #[test]
    fn own_node_services_not_in_egress() {
        // Egress only concerns *remote* nodes; the own node's own services are ingress.
        let rules = egress(EGRESS_FIXTURE, "Cabin");
        // From Cabin, `web` is local (ingress), so it must not appear in egress.
        assert!(!rules.iter().any(|r| r.name.contains("web")));
    }
}
