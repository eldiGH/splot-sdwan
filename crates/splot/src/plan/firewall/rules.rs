//! Rules: the flows this node lets through, to the services on it (ingress) and,
//! from the networks behind it, to services elsewhere (egress). One rule per
//! flow and zone its sources arrive in.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use super::zone_ref::ZoneRef;
use crate::{
    model::{
        Network,
        host::{HostAddress, HostRef},
        node::Node,
        service::{Service, Source},
    },
    plan::{list, proto_port},
    types::{identifier::Identifier, ip::Ipv4Network, port::PortOrRange, protocol::Protocol},
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

/// Where a rule lets traffic go on the node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Destination {
    /// The node itself.
    Node,
    /// Through the node, into one of its zones.
    Zone(ZoneRef),
}

/// A flow this node accepts: to one service of one host, from the sources its
/// `allowFrom` resolves to here that arrive in one zone.
#[derive(Debug)]
pub struct Rule {
    pub host: HostRef,
    pub service: Identifier,
    /// One service can need both on one node (a global client with IPs on two
    /// nodes), so the direction is part of what tells two rules apart.
    pub direction: Direction,
    /// The zone the sources arrive in. A flow has a rule per zone, so the zone
    /// is part of what tells two rules apart too.
    pub from: ZoneRef,
    pub sources: Vec<Ipv4Network>,
    /// Follows from the rest: the node itself, the host's zone, or the mesh.
    pub to: Destination,
    pub destinations: Vec<Ipv4Network>,
    pub port: PortOrRange,
    pub proto: BTreeSet<Protocol>,
}

/// One service of one host, and who its `allowFrom` lets in.
struct Flow<'a> {
    host: &'a HostRef,
    name: &'a Identifier,
    service: &'a Service,
}

impl Flow<'_> {
    /// Into `own`, to the host's addresses `here` on it: its own to the node
    /// itself, anyone else's into the zone it's in. Left out: sources in that
    /// zone (their traffic never passes the node), and the node's own zones
    /// toward the node itself (what reaches the router from them is the
    /// operator's).
    fn ingress(&self, own: &Node, here: &[&HostAddress]) -> Vec<Rule> {
        let mut destinations: BTreeMap<Destination, Vec<Ipv4Network>> = BTreeMap::new();
        for address in here {
            let to = match self.host {
                HostRef::Node(_) => Destination::Node,
                _ => Destination::Zone(ZoneRef::on(own.name(), address.place())),
            };
            destinations
                .entry(to)
                .or_default()
                .push(Ipv4Network::host(address.ip()));
        }

        let sources = by_zone(own, self.service.sources().everywhere());
        let mut rules = Vec::new();
        for (to, destinations) in destinations {
            for (from, sources) in &sources {
                let crosses = match (from, &to) {
                    (ZoneRef::Mesh, _) => true,
                    (ZoneRef::Named(_), Destination::Node) => false,
                    (ZoneRef::Named(_), Destination::Zone(zone)) => from != zone,
                };
                if crosses {
                    rules.push(self.rule(
                        Direction::Ingress,
                        from.clone(),
                        sources.clone(),
                        to.clone(),
                        destinations.clone(),
                    ));
                }
            }
        }
        rules
    }

    /// Out of `own`, over the mesh, to the host's addresses `elsewhere`: from
    /// the sources behind `own`, in its zones or on its hub.
    fn egress(&self, own: &Node, elsewhere: &[&HostAddress]) -> Vec<Rule> {
        if elsewhere.is_empty() {
            return Vec::new();
        }
        let destinations: Vec<Ipv4Network> = elsewhere
            .iter()
            .map(|address| Ipv4Network::host(address.ip()))
            .collect();
        let behind = self
            .service
            .sources()
            .everywhere()
            .filter(|source| source.place().node() == Some(own.name()));

        by_zone(own, behind)
            .into_iter()
            .map(|(from, sources)| {
                self.rule(
                    Direction::Egress,
                    from,
                    sources,
                    Destination::Zone(ZoneRef::Mesh),
                    destinations.clone(),
                )
            })
            .collect()
    }

    fn rule(
        &self,
        direction: Direction,
        from: ZoneRef,
        sources: Vec<Ipv4Network>,
        to: Destination,
        destinations: Vec<Ipv4Network>,
    ) -> Rule {
        Rule {
            host: self.host.clone(),
            service: self.name.clone(),
            direction,
            from,
            sources,
            to,
            destinations,
            port: self.service.port().internal(),
            proto: self.service.proto().clone(),
        }
    }
}

/// The sources, by the zone of `own` each arrives in.
fn by_zone<'a>(
    own: &Node,
    sources: impl Iterator<Item = &'a Source>,
) -> BTreeMap<ZoneRef, Vec<Ipv4Network>> {
    let mut zones: BTreeMap<ZoneRef, Vec<Ipv4Network>> = BTreeMap::new();
    for source in sources {
        zones
            .entry(ZoneRef::on(own.name(), source.place()))
            .or_default()
            .push(source.network());
    }
    zones
}

/// The rules on `own`: to the hosts on it first, then to hosts elsewhere. A
/// global client's mesh IP is on no node, so it gets none. `mesh` says whether
/// `own` has a mesh zone: without one, what comes from or goes to the mesh
/// arrives in a zone of the operator's, and gets no rule.
pub(super) fn rules(network: &Network, own: &Node, mesh: bool) -> Vec<Rule> {
    let mut ingress = Vec::new();
    let mut egress = Vec::new();

    for host in network.hosts() {
        let here: Vec<&HostAddress> = host.addresses_on(|node| node == own.name()).collect();
        let elsewhere: Vec<&HostAddress> = host.addresses_on(|node| node != own.name()).collect();

        for (name, service) in network.services_of(host) {
            let flow = Flow {
                host: host.id(),
                name,
                service,
            };
            ingress.extend(flow.ingress(own, &here));
            egress.extend(flow.egress(own, &elsewhere));
        }
    }

    let mut rules = ingress;
    rules.extend(egress);
    if !mesh {
        let mesh_zone = Destination::Zone(ZoneRef::Mesh);
        rules.retain(|rule| rule.from != ZoneRef::Mesh && rule.to != mesh_zone);
    }
    rules
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node => f.write_str("the node"),
            Self::Zone(zone) => write!(f, "{zone}"),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let direction = match self.direction {
            Direction::Ingress => "in",
            Direction::Egress => "out",
        };

        write!(
            f,
            "accept {direction} {} {}: {} from {} {} to {} {}",
            self.host,
            self.service,
            proto_port(&self.proto, &self.port),
            self.from,
            list(&self.sources),
            self.to,
            list(&self.destinations)
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

    /// The rules on `own`, with a mesh zone or without, as the plan shows them.
    fn placed_with(yaml: &str, own: &str, mesh: bool) -> Vec<String> {
        let network = checked(yaml);
        rules(&network, network.node(&id(own)).unwrap(), mesh)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn placed(yaml: &str, own: &str) -> Vec<String> {
        placed_with(yaml, own, true)
    }

    /// Those of one service, `Home.nas https`.
    fn of(rules: &[String], service: &str) -> Vec<String> {
        rules
            .iter()
            .filter(|rule| rule.contains(&format!(" {service}:")))
            .cloned()
            .collect()
    }

    // Home: ssh on the router; a lan with a pc and a nas, an iot zone with a
    // printer; a hub with a camera and a doorbell. Cabin: a lan with a tv. Phone
    // has a mesh IP and an IP on Home's lan.
    const SITES: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh: { port: 22, proto: tcp, allowFrom: [Phone, Home.lan] }
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          pc: { ip: 192.168.1.10, macs: AA:BB:CC:DD:EE:01 }
          nas:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:02
            services:
              https: { port: 443, proto: tcp, allowFrom: [Phone, Home.lan, Cabin.lan] }
      iot:
        address: 192.168.3.1/24
        devices:
          printer:
            ip: 192.168.3.20
            macs: AA:BB:CC:DD:EE:03
            services:
              ipp: { port: 631, proto: tcp, allowFrom: [Home.lan, $node] }
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, allowFrom: [Phone, Home.pc, Home.doorbell] }
        doorbell:
          publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
          ip: 10.100.49.11
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          tv:
            ip: 192.168.2.30
            macs: AA:BB:CC:DD:EE:04
            services:
              cast: { port: 8009, proto: tcp, allowFrom: [Home.pc, Home.doorbell] }
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.1.10
    macs: AA:BB:CC:DD:EE:05
    ips:
      Home: { lan: 192.168.1.50 }
";

    #[test]
    fn a_service_on_the_node_itself_is_let_in_from_the_mesh_alone() {
        // Phone's lan IP and Home.lan reach the router from one of its own zones:
        // that's the operator's.
        assert_eq!(
            of(&placed(SITES, "Home"), "Home ssh"),
            [
                "accept in Home ssh: tcp/22 from mesh [10.100.1.10/32] to the node [10.100.0.1/32, 192.168.3.1/32, 192.168.1.1/32]"
            ]
        );
    }

    #[test]
    fn a_source_in_the_destinations_own_zone_gets_no_rule() {
        // Phone's lan IP and Home.lan are on the nas's own link; Cabin.lan comes
        // over the mesh.
        assert_eq!(
            of(&placed(SITES, "Home"), "Home.nas https"),
            [
                "accept in Home.nas https: tcp/443 from mesh [10.100.1.10/32, 192.168.2.0/24] to lan [192.168.1.20/32]"
            ]
        );
    }

    #[test]
    fn a_flow_between_two_zones_of_a_site_goes_from_one_to_the_other() {
        assert_eq!(
            of(&placed(SITES, "Home"), "Home.printer ipp"),
            [
                "accept in Home.printer ipp: tcp/631 from lan [192.168.1.0/24] to iot [192.168.3.20/32]"
            ]
        );
    }

    #[test]
    fn the_router_itself_needs_no_rule() {
        // What the router sends leaves through its output, which splot leaves
        // open: `$node` names no source that needs letting through.
        let sites = SITES.replace("allowFrom: [Home.lan, $node]", "allowFrom: $node");
        for node in ["Home", "Cabin"] {
            let rules = placed(&sites, node);
            assert!(of(&rules, "Home.printer ipp").is_empty(), "{rules:?}");
        }
    }

    #[test]
    fn sources_in_two_zones_get_a_rule_each() {
        // The camera is on the hub, reached through the mesh zone: Phone comes
        // from the mesh and from the lan. The doorbell, the camera's neighbour on
        // the hub, still needs a rule: hub clients reach each other through the
        // node.
        assert_eq!(
            of(&placed(SITES, "Home"), "Home.camera rtsp"),
            [
                "accept in Home.camera rtsp: tcp/554 from mesh [10.100.1.10/32, 10.100.49.11/32] to mesh [10.100.49.10/32]",
                "accept in Home.camera rtsp: tcp/554 from lan [192.168.1.10/32, 192.168.1.50/32] to mesh [10.100.49.10/32]",
            ]
        );
    }

    #[test]
    fn a_flow_across_the_mesh_is_let_out_at_one_end_and_in_at_the_other() {
        assert_eq!(
            of(&placed(SITES, "Home"), "Cabin.tv cast"),
            [
                "accept out Cabin.tv cast: tcp/8009 from mesh [10.100.49.11/32] to mesh [192.168.2.30/32]",
                "accept out Cabin.tv cast: tcp/8009 from lan [192.168.1.10/32] to mesh [192.168.2.30/32]",
            ]
        );
        assert_eq!(
            of(&placed(SITES, "Cabin"), "Cabin.tv cast"),
            [
                "accept in Cabin.tv cast: tcp/8009 from mesh [10.100.49.11/32, 192.168.1.10/32] to lan [192.168.2.30/32]"
            ]
        );
    }

    #[test]
    fn only_sources_behind_the_node_are_let_out() {
        // Phone reaches Home over the mesh on its own, and Home's pc and doorbell
        // aren't behind Cabin: Cabin lets out only its lan, toward the nas.
        assert_eq!(
            placed(SITES, "Cabin"),
            [
                "accept in Cabin.tv cast: tcp/8009 from mesh [10.100.49.11/32, 192.168.1.10/32] to lan [192.168.2.30/32]",
                "accept out Home.nas https: tcp/443 from lan [192.168.2.0/24] to mesh [192.168.1.20/32]",
            ]
        );
    }

    #[test]
    fn without_a_mesh_zone_nothing_comes_from_or_goes_to_the_mesh() {
        // As on a node whose WireGuard splot leaves alone: what crosses the mesh
        // arrives in a zone of the operator's, under their rules.
        assert_eq!(
            placed_with(SITES, "Home", false),
            [
                "accept in Home.printer ipp: tcp/631 from lan [192.168.1.0/24] to iot [192.168.3.20/32]"
            ]
        );
    }

    #[test]
    fn one_service_can_need_an_ingress_and_an_egress_rule_on_one_node() {
        // Laptop lives on both Home's and Cabin's LAN and offers ssh. From Home's
        // view that's an ingress rule (its Home IP, from Cabin's pc over the
        // mesh) and an egress rule (its Cabin IP, from Home's lan): the same host
        // and service, told apart by direction.
        let yaml = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
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
        assert_eq!(
            of(&placed(yaml, "Home"), "Laptop ssh"),
            [
                "accept in Laptop ssh: tcp/22 from mesh [192.168.2.10/32] to lan [192.168.1.50/32]",
                "accept out Laptop ssh: tcp/22 from lan [192.168.1.0/24] to mesh [192.168.2.50/32]",
            ]
        );
    }

    #[test]
    fn no_allowfrom_no_rule() {
        // A service only forwarded from the WAN.
        let rules = placed(
            "
meshNetwork: 10.100.0.0/24
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
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
            "Home",
        );
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn a_reference_with_nothing_behind_it_gives_no_rule() {
        // Cabin has no zones and no hub: `Cabin` names no network.
        let yaml = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh: { port: 22, proto: tcp, allowFrom: Cabin }
  Cabin:
    platform:
      os: openwrt
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
";
        assert!(placed(yaml, "Home").is_empty());
        assert!(placed(yaml, "Cabin").is_empty());
    }

    #[test]
    fn a_source_two_references_name_is_listed_once() {
        // Phone is named directly and by its tag.
        let rules = placed(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
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
        assert_eq!(
            rules,
            ["accept in Home ssh: tcp/22 from mesh [10.100.0.100/32] to the node [10.100.0.1/32]"]
        );
    }
}
