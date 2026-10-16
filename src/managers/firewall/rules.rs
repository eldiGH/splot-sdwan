use std::fmt;

use crate::{
    config::Config,
    managers::{
        UciSection, UciSectionBuilder,
        firewall::{consts::FIREWALL_FILE_NAME, types::FirewallAction},
        naming,
    },
    model::{
        Network,
        host::{HostAddress, HostRef},
        service::{Service, Source},
    },
    protocol::Protocols,
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange},
};

/// Where the protected host is, seen from the node being configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDirection {
    /// A host on this node: its own services, its devices and hub clients, and
    /// global clients in its zones.
    Ingress,
    /// A host on another node, reached from sources local to this node.
    Egress,
}

pub struct FirewallRule {
    pub name: String,
    pub direction: RuleDirection,
    pub src_ip: Vec<Ipv4Network>,
    pub proto: Protocols,
    pub dest_port: PortOrRange,
    pub dest_ip: Vec<Ipv4Network>,
    pub target: FirewallAction,
}

impl UciSection for FirewallRule {
    const FILE: &'static str = FIREWALL_FILE_NAME;

    fn section_type(&self) -> &str {
        "rule"
    }

    /// The direction is part of the id: one service can need an ingress and an
    /// egress rule on the same node (a global client with IPs on two nodes).
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let direction = match self.direction {
            RuleDirection::Ingress => "in",
            RuleDirection::Egress => "out",
        };

        [direction, self.name.as_str()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed(&self.name))
            .set("src", "*")
            .set("dest", "*")
            .set("dest_port", self.dest_port.to_string())
            .set("target", self.target.to_string())
            .extend_list("dest_ip", self.dest_ip.iter())
            .extend_list("src_ip", self.src_ip.iter())
            .extend_list("proto", self.proto.iter())
    }
}

fn generate_rule_from_service(
    direction: RuleDirection,
    service_name: &Identifier,
    service: &Service,
    dest_addresses: &[&HostAddress],
    owner_name: impl fmt::Display,
    own_name: &Identifier,
    src_ip_filter: Option<&[Ipv4Network]>,
) -> Option<FirewallRule> {
    let src_ips: Vec<Ipv4Network> = service
        .sources()
        .on(own_name)
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

    if src_ips.is_empty() {
        return None;
    }

    let rule_name = format!("{}_{}", owner_name, service_name);

    Some(FirewallRule {
        src_ip: src_ips,
        name: rule_name,
        direction,
        dest_ip: dest_addresses
            .iter()
            .map(|address| Ipv4Network::host(address.ip()))
            .collect(),
        dest_port: service.port().internal(),
        proto: service.proto().clone().into(),
        target: FirewallAction::Accept,
    })
}

/// The host part of a rule's name. A host inside a node goes by its local name on
/// that node, and by both names elsewhere.
fn owner_name(host: &HostRef, direction: RuleDirection) -> String {
    match (host, direction) {
        (HostRef::Local { node, name }, RuleDirection::Egress) => format!("{node}_{name}"),
        _ => host.name().to_string(),
    }
}

/// A rule for each service of every host with addresses on this node (ingress)
/// or on other nodes (egress), toward those addresses. A global client's mesh IP
/// is on no node, so it gets no rule.
fn host_rules(
    network: &Network,
    direction: RuleDirection,
    own_name: &Identifier,
    src_ip_filter: Option<&[Ipv4Network]>,
) -> Vec<FirewallRule> {
    let on = |node: &Identifier| match direction {
        RuleDirection::Ingress => node == own_name,
        RuleDirection::Egress => node != own_name,
    };
    let mut rules = Vec::new();

    for host in network.hosts() {
        let addresses: Vec<&HostAddress> = host.addresses_on(on).collect();

        if addresses.is_empty() {
            continue;
        }

        let owner = owner_name(host.id(), direction);

        for (service_name, service) in network.services_of(host) {
            rules.extend(generate_rule_from_service(
                direction,
                service_name,
                service,
                &addresses,
                &owner,
                own_name,
                src_ip_filter,
            ));
        }
    }

    rules
}

pub fn get_firewall_ingress_rules(network: &Network, own_name: &Identifier) -> Vec<FirewallRule> {
    host_rules(network, RuleDirection::Ingress, own_name, None)
}

pub fn get_firewall_egress_rules(
    config: &Config,
    network: &Network,
    own_name: &Identifier,
) -> Vec<FirewallRule> {
    let local_networks: Vec<Ipv4Network> = config
        .nodes
        .get(own_name)
        .expect("own node not found - should be validated before running manager")
        .networks()
        .collect();

    host_rules(
        network,
        RuleDirection::Egress,
        own_name,
        Some(&local_networks),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn ingress(yaml: &str, own: &str) -> Vec<FirewallRule> {
        let (_, network) = checked(yaml);
        get_firewall_ingress_rules(&network, &id(own))
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
        let rule = rules.iter().find(|r| r.name.contains("ssh")).unwrap();
        assert!(
            rule.src_ip
                .iter()
                .any(|n| n.to_string() == "10.100.0.100/32")
        );
    }

    fn egress(yaml: &str, own: &str) -> Vec<FirewallRule> {
        let (cfg, network) = checked(yaml);
        get_firewall_egress_rules(&cfg, &network, &id(own))
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

    #[test]
    fn ingress_and_egress_rule_of_one_service_get_distinct_sections() {
        // Laptop lives on both Home's and Cabin's LAN and offers ssh. From Home's
        // view that's an ingress rule (its Home IP) and an egress rule (its Cabin
        // IP). Both used to be `spl_Laptop_ssh`, and uci merged them into one rule
        // allowing the cross-product of all sources and destinations.
        let yaml = "
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
        // The first command of a rule creates its section.
        let sections = |rules: Vec<FirewallRule>| -> Vec<String> {
            rules
                .iter()
                .map(|rule| rule.to_uci_commands()[0].to_string())
                .collect()
        };
        let ingress = sections(ingress(yaml, "Home"));
        let egress = sections(egress(yaml, "Home"));

        let laptop_in = "set firewall.spl_rule_in_Laptop_ssh='rule'".to_owned();
        let laptop_out = "set firewall.spl_rule_out_Laptop_ssh='rule'".to_owned();
        assert!(ingress.contains(&laptop_in), "{ingress:?}");
        assert!(!ingress.contains(&laptop_out), "{ingress:?}");
        assert!(egress.contains(&laptop_out), "{egress:?}");
        assert!(!egress.contains(&laptop_in), "{egress:?}");
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
            .find(|r| r.name == "camera_rtsp")
            .expect("ingress rule for the camera missing");
        assert_eq!(networks(&rule.dest_ip), ["10.100.49.10/32"]);
        let src = networks(&rule.src_ip);
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
            .find(|r| r.name == "Home_camera_rtsp")
            .expect("egress rule for the camera missing");
        assert_eq!(networks(&rule.dest_ip), ["10.100.49.10/32"]);
        assert_eq!(networks(&rule.src_ip), ["192.168.2.10/32"]);
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
        assert_eq!(networks(&rule.src_ip), ["10.100.0.100/32"]);
    }

    #[test]
    fn hub_clients_are_local_sources_of_their_hub_node() {
        // The doorbell reaches Cabin's web through Home, so Home lets it out.
        let rules = egress(HUB_FIXTURE, "Home");
        let rule = rules
            .iter()
            .find(|r| r.name == "Cabin_web")
            .expect("egress rule for Cabin's web missing");
        assert_eq!(networks(&rule.src_ip), ["10.100.49.11/32"]);
    }
}
