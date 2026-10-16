//! Rules: the flows this node lets through, to the services on it (ingress) and,
//! from the networks behind it, to services elsewhere (egress).

use std::{collections::BTreeSet, fmt};

use crate::{
    model::{
        Network,
        host::{HostAddress, HostRef},
        node::Node,
        service::{Service, Source},
    },
    protocol::Protocol,
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange},
};

/// Where the protected host is, seen from the node being configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A host on this node: its own services, its devices and hub clients, and
    /// global clients in its zones.
    Ingress,
    /// A host on another node, reached from sources local to this node.
    Egress,
}

/// A flow this node accepts: to one service of one host, from the sources its
/// `allowFrom` resolves to here.
#[derive(Debug)]
pub struct Rule {
    pub host: HostRef,
    pub service: Identifier,
    /// One service can need both on one node (a global client with IPs on two
    /// nodes), so the direction is part of what tells two rules apart.
    pub direction: Direction,
    pub sources: Vec<Ipv4Network>,
    pub destinations: Vec<Ipv4Network>,
    pub port: PortOrRange,
    pub proto: BTreeSet<Protocol>,
}

fn rule(
    direction: Direction,
    host: &HostRef,
    service_name: &Identifier,
    service: &Service,
    dest_addresses: &[&HostAddress],
    own: &Node,
    src_ip_filter: Option<&[Ipv4Network]>,
) -> Option<Rule> {
    let sources: Vec<Ipv4Network> = service
        .sources()
        .on(own.name())
        .map(Source::network)
        // skip same-LAN sources — they don't traverse this router's firewall
        .filter(|network| {
            dest_addresses
                .iter()
                .any(|dest_address| !dest_address.shares_link(network.ip()))
        })
        .filter(|network| {
            let Some(src_ip_filter) = src_ip_filter else {
                return true;
            };

            src_ip_filter
                .iter()
                .any(|address| address.contains(network.ip()))
        })
        .collect();

    if sources.is_empty() {
        return None;
    }

    Some(Rule {
        host: host.clone(),
        service: service_name.clone(),
        direction,
        sources,
        destinations: dest_addresses
            .iter()
            .map(|address| Ipv4Network::host(address.ip()))
            .collect(),
        port: service.port().internal(),
        proto: service.proto().clone(),
    })
}

/// A rule for each service of every host with addresses on this node (ingress)
/// or on other nodes (egress), toward those addresses. A global client's mesh IP
/// is on no node, so it gets no rule.
fn host_rules(
    network: &Network,
    direction: Direction,
    own: &Node,
    src_ip_filter: Option<&[Ipv4Network]>,
) -> Vec<Rule> {
    let on = |node: &Identifier| match direction {
        Direction::Ingress => node == own.name(),
        Direction::Egress => node != own.name(),
    };
    let mut rules = Vec::new();

    for host in network.hosts() {
        let addresses: Vec<&HostAddress> = host.addresses_on(on).collect();

        if addresses.is_empty() {
            continue;
        }

        for (service_name, service) in network.services_of(host) {
            rules.extend(rule(
                direction,
                host.id(),
                service_name,
                service,
                &addresses,
                own,
                src_ip_filter,
            ));
        }
    }

    rules
}

pub(super) fn ingress_rules(network: &Network, own: &Node) -> Vec<Rule> {
    host_rules(network, Direction::Ingress, own, None)
}

pub(super) fn egress_rules(network: &Network, own: &Node) -> Vec<Rule> {
    let local_networks: Vec<Ipv4Network> = own.networks().collect();

    host_rules(network, Direction::Egress, own, Some(&local_networks))
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let direction = match self.direction {
            Direction::Ingress => "in",
            Direction::Egress => "out",
        };

        write!(
            f,
            "accept {direction} {} {}: {} from {} to {}",
            self.host,
            self.service,
            super::super::proto_port(&self.proto, &self.port),
            super::super::list(&self.sources),
            super::super::list(&self.destinations)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn ingress(yaml: &str, own: &str) -> Vec<Rule> {
        let network = checked(yaml);
        ingress_rules(&network, network.node(&id(own)).unwrap())
    }

    #[test]
    fn allowfrom_produces_ingress_rule() {
        // Home node service ssh with allowFrom: Phone → rule with Phone's meshIp in src_ip.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
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
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
            "Home",
        );
        let rule = rules
            .iter()
            .find(|r| r.service.as_ref() == "ssh")
            .expect("ssh rule missing");
        assert!(
            rule.sources
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
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
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
    macs: AA:BB:CC:DD:EE:01
    ips:
      Home:
        lan: 192.168.1.60
",
            "Home",
        );
        assert!(
            !rules.iter().any(|r| r.service.as_ref() == "print"),
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
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
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
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: Phone
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
            "Home",
        );
        let rule = rules.iter().find(|r| r.service.as_ref() == "ssh").unwrap();
        assert!(
            rule.sources
                .iter()
                .any(|n| n.to_string() == "10.100.0.100/32")
        );
    }

    fn egress(yaml: &str, own: &str) -> Vec<Rule> {
        let network = checked(yaml);
        egress_rules(&network, network.node(&id(own)).unwrap())
    }

    // Home-local workstation (tag `staff`) wants to reach Cabin's `web` service.
    // From Home's perspective this is egress: Home must ACCEPT the local source
    // toward the remote (mesh-reachable) destination.
    const EGRESS_FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
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
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
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
            .find(|r| r.service.as_ref() == "web")
            .expect("egress rule for Cabin web missing");
        // src is the Home-local workstation; dest includes Cabin's mesh host IP.
        assert!(
            rule.sources
                .iter()
                .any(|n| n.to_string() == "192.168.1.10/32"),
            "local source workstation missing from src_ip"
        );
        assert!(
            rule.destinations
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
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
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
            !rules.iter().any(|r| r.service.as_ref() == "web"),
            "non-local source should not produce an egress rule on Home"
        );
    }

    #[test]
    fn own_node_services_not_in_egress() {
        // Egress only concerns *remote* nodes; the own node's own services are ingress.
        let rules = egress(EGRESS_FIXTURE, "Cabin");
        // From Cabin, `web` is local (ingress), so it must not appear in egress.
        assert!(!rules.iter().any(|r| r.service.as_ref() == "web"));
    }

    // Laptop lives on both Home's and Cabin's LAN and offers ssh.
    const LAPTOP_ON_TWO_NODES: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          pc:
            ip: 192.168.2.10
            macs: AA:BB:CC:DD:EE:01
clients:
  Laptop:
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home: { lan: 192.168.1.50 }
      Cabin: { lan: 192.168.2.50 }
    services:
      ssh: { port: 22, proto: tcp, allowFrom: [Cabin.pc, Home.lan] }
";

    #[test]
    fn one_service_can_need_an_ingress_and_an_egress_rule_on_one_node() {
        // Laptop lives on both Home's and Cabin's LAN and offers ssh. From Home's
        // view that's an ingress rule (its Home IP) and an egress rule (its Cabin
        // IP): the same host and service, told apart by direction.
        let ingress = ingress(LAPTOP_ON_TWO_NODES, "Home");
        let egress = egress(LAPTOP_ON_TWO_NODES, "Home");

        let laptop = |rules: &[Rule]| -> Vec<String> {
            rules
                .iter()
                .filter(|rule| rule.host.to_string() == "Laptop")
                .map(|rule| {
                    format!(
                        "{:?} {}",
                        rule.direction,
                        networks(&rule.destinations).join(" ")
                    )
                })
                .collect()
        };
        assert_eq!(laptop(&ingress), ["Ingress 192.168.1.50/32"]);
        assert_eq!(laptop(&egress), ["Egress 192.168.2.50/32"]);
    }

    // Home's hub has a camera (rtsp) and a doorbell. Cabin has a pc and a web
    // service the doorbell may use.
    const HUB_FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
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
          services:
            rtsp: { port: 554, proto: tcp, allowFrom: [Phone, Cabin.pc, Home.doorbell] }
        doorbell:
          publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
          ip: 10.100.49.11
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          pc: { ip: 192.168.2.10, macs: AA:BB:CC:DD:EE:01 }
    services:
      web: { port: 80, proto: tcp, allowFrom: Home.doorbell }
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.1.10
";

    fn networks(list: &[Ipv4Network]) -> Vec<String> {
        list.iter().map(|network| network.to_string()).collect()
    }

    #[test]
    fn hub_client_service_gets_an_ingress_rule_on_its_hub_node() {
        let rules = ingress(HUB_FIXTURE, "Home");
        let rule = rules
            .iter()
            .find(|r| r.host.to_string() == "Home.camera" && r.service.as_ref() == "rtsp")
            .expect("ingress rule for the camera missing");
        assert_eq!(networks(&rule.destinations), ["10.100.49.10/32"]);
        let src = networks(&rule.sources);
        assert!(src.contains(&"10.100.1.10/32".to_owned()), "{src:?}");
        // Same hub, still a rule: hub clients reach each other through the node
        // (routed, not bridged), so the same-network filter must keep them.
        assert!(src.contains(&"10.100.49.11/32".to_owned()), "{src:?}");
    }

    #[test]
    fn hub_client_service_gets_an_egress_rule_on_other_nodes() {
        let rules = egress(HUB_FIXTURE, "Cabin");
        let rule = rules
            .iter()
            .find(|r| r.host.to_string() == "Home.camera" && r.service.as_ref() == "rtsp")
            .expect("egress rule for the camera missing");
        assert_eq!(networks(&rule.destinations), ["10.100.49.10/32"]);
        assert_eq!(networks(&rule.sources), ["192.168.2.10/32"]);
    }

    #[test]
    fn a_reference_with_nothing_behind_it_gives_no_rule() {
        // Cabin has no zones and no hub: `Cabin` names no network. `$node` on Home,
        // which has no zones either, names none.
        let yaml = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh: { port: 22, proto: tcp, allowFrom: Cabin }
      dns: { port: 53, proto: udp, allowFrom: $node }
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
";
        assert!(ingress(yaml, "Home").is_empty());
        assert!(egress(yaml, "Cabin").is_empty());
    }

    #[test]
    fn a_source_two_references_name_is_listed_once() {
        // Phone is named directly and by its tag.
        let rules = ingress(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh: { port: 22, proto: tcp, allowFrom: [Phone, mobile] }
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    tags: mobile
",
            "Home",
        );
        let [rule] = rules.as_slice() else {
            panic!("expected one rule, got {}", rules.len());
        };
        assert_eq!(networks(&rule.sources), ["10.100.0.100/32"]);
    }

    #[test]
    fn hub_clients_are_local_sources_of_their_hub_node() {
        // The doorbell reaches Cabin's web through Home, so Home lets it out.
        let rules = egress(HUB_FIXTURE, "Home");
        let rule = rules
            .iter()
            .find(|r| r.host.to_string() == "Cabin" && r.service.as_ref() == "web")
            .expect("egress rule for Cabin's web missing");
        assert_eq!(networks(&rule.sources), ["10.100.49.11/32"]);
    }
}
