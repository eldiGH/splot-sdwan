//! Rules as uci `rule` sections.

use super::{qualified_host_id, zone_name};
use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    model::host::HostRef,
    plan::firewall::rules::{Destination, Direction, Rule},
};

fn direction(direction: Direction) -> &'static str {
    match direction {
        Direction::Ingress => "in",
        Direction::Egress => "out",
    }
}

/// The host's part of a rule's id: a host inside a node by its local name on that
/// node, and by both names elsewhere.
fn host_id(host: &HostRef, direction: Direction) -> Vec<&str> {
    match direction {
        Direction::Ingress => vec![host.name().as_ref()],
        Direction::Egress => qualified_host_id(host),
    }
}

impl UciSection for Rule {
    fn section_type(&self) -> &str {
        "rule"
    }

    /// The direction and the source zone are part of the id: one service can
    /// need an ingress and an egress rule on the same node (a global client with
    /// IPs on two nodes), and a rule for each zone its sources arrive in. A
    /// forward from another node's WAN goes by that node instead, one rule each.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = vec![direction(self.direction)];
        id.extend(host_id(&self.host, self.direction));
        id.push(self.service.as_ref());
        match &self.via {
            Some(via) => id.extend(["via", via.as_ref()]),
            None => id.extend(["from", zone_name(&self.from)]),
        }
        id
    }

    /// The label is in the config's notation, so what LuCI shows can be searched
    /// for in `splot.yml`: `[SPLOT] out: Cabin.camera rtsp, from lan`, and
    /// `[SPLOT] in: Cabin.camera rtsp, via Home` for Home's forward. Without a
    /// `dest`, fw4 puts the rule in the source zone's input chain: to the node
    /// itself.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let from = zone_name(&self.from);
        let whence = match &self.via {
            Some(via) => format!("via {via}"),
            None => format!("from {from}"),
        };
        let label = format!(
            "{}: {} {}, {whence}",
            direction(self.direction),
            self.host,
            self.service
        );
        let dest = match &self.to {
            Destination::Node => None,
            Destination::Zone(zone) => Some(zone_name(zone)),
        };

        section
            .set("name", naming::name_prefixed(&label))
            .set("src", from)
            .set_if_some("dest", dest)
            .set("dest_port", self.port.to_string())
            .set("target", "ACCEPT")
            .extend_list("dest_ip", &self.destinations)
            .extend_list("src_ip", &self.sources)
            .extend_list("proto", &self.proto)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        plan::{self, firewall::zone_ref::ZoneRef},
        test_support::checked,
    };

    /// Cabin's camera's rtsp, from `from` to `to`.
    fn camera_rule(direction: Direction, from: ZoneRef, to: Destination) -> Rule {
        Rule {
            host: HostRef::Local {
                node: "Cabin".parse().unwrap(),
                name: "camera".parse().unwrap(),
            },
            service: "rtsp".parse().unwrap(),
            direction,
            from,
            sources: vec!["192.168.1.0/24".parse().unwrap()],
            to,
            destinations: vec!["192.168.2.30/32".parse().unwrap()],
            port: "554".parse().unwrap(),
            proto: BTreeSet::from([crate::types::protocol::Protocol::Tcp]),
            via: None,
        }
    }

    fn lan() -> ZoneRef {
        ZoneRef::Named("lan".parse().unwrap())
    }

    fn commands(rule: &Rule) -> Vec<String> {
        rule.to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// A rendered rule's `option` line, if it has one.
    fn option(rule: &Rule, option: &str) -> Option<String> {
        commands(rule)
            .into_iter()
            .find(|command| command.contains(&format!(".{option}=")))
    }

    #[test]
    fn a_rule_is_labelled_in_config_notation_with_its_direction_and_source_zone() {
        // What LuCI shows can be searched for in splot.yml; the section names keep
        // uci's character set.
        let out = camera_rule(Direction::Egress, lan(), Destination::Zone(ZoneRef::Mesh));
        assert_eq!(
            option(&out, "name").unwrap(),
            "set firewall.spl_rule_out_Cabin_camera_rtsp_from_lan.name='[SPLOT] out: Cabin.camera rtsp, from lan'"
        );
        let into = camera_rule(Direction::Ingress, ZoneRef::Mesh, Destination::Zone(lan()));
        assert_eq!(
            option(&into, "name").unwrap(),
            "set firewall.spl_rule_in_camera_rtsp_from_spl_mesh.name='[SPLOT] in: Cabin.camera rtsp, from spl_mesh'"
        );
    }

    #[test]
    fn a_forward_from_another_nodes_wan_is_a_rule_of_its_own() {
        // Beside what allowFrom grants from the mesh, and named after the node
        // that forwards it, as `wan.via` names it.
        let granted = camera_rule(Direction::Ingress, ZoneRef::Mesh, Destination::Zone(lan()));
        let forwarded = Rule {
            via: Some("Home".parse().unwrap()),
            ..camera_rule(Direction::Ingress, ZoneRef::Mesh, Destination::Zone(lan()))
        };
        assert_eq!(
            option(&forwarded, "name").unwrap(),
            "set firewall.spl_rule_in_camera_rtsp_via_Home.name='[SPLOT] in: Cabin.camera rtsp, via Home'"
        );
        assert_ne!(commands(&granted)[0], commands(&forwarded)[0]);
        assert!(
            option(&forwarded, "src")
                .unwrap()
                .ends_with(".src='spl_mesh'")
        );
    }

    #[test]
    fn a_rule_names_its_zones_as_fw4_knows_them() {
        // fw4 puts a rule with a `dest` in the source zone's forward chain.
        let into = camera_rule(Direction::Ingress, ZoneRef::Mesh, Destination::Zone(lan()));
        let section = "set firewall.spl_rule_in_camera_rtsp_from_spl_mesh";
        assert_eq!(
            option(&into, "src").unwrap(),
            format!("{section}.src='spl_mesh'")
        );
        assert_eq!(
            option(&into, "dest").unwrap(),
            format!("{section}.dest='lan'")
        );

        let out = camera_rule(Direction::Egress, lan(), Destination::Zone(ZoneRef::Mesh));
        let section = "set firewall.spl_rule_out_Cabin_camera_rtsp_from_lan";
        assert_eq!(option(&out, "src").unwrap(), format!("{section}.src='lan'"));
        assert_eq!(
            option(&out, "dest").unwrap(),
            format!("{section}.dest='spl_mesh'")
        );
    }

    #[test]
    fn a_rule_to_the_node_itself_has_no_dest() {
        // fw4 puts a rule without a `dest` in the source zone's input chain.
        let to_node = camera_rule(Direction::Ingress, ZoneRef::Mesh, Destination::Node);
        assert!(
            option(&to_node, "src")
                .unwrap()
                .ends_with(".src='spl_mesh'")
        );
        assert_eq!(option(&to_node, "dest"), None, "{:?}", commands(&to_node));
    }

    #[test]
    fn ingress_and_egress_rule_of_one_service_get_distinct_sections() {
        // Laptop lives on both Home's and Cabin's LAN and offers ssh. From Home's
        // view that's an ingress rule (its Home IP, from Cabin's pc over the
        // mesh) and an egress rule (its Cabin IP, from Home's lan). Both used to
        // be `spl_Laptop_ssh`, and uci merged them into one rule allowing the
        // cross-product of all sources and destinations.
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
        // The first command of a rule creates its section.
        let plan = plan::plan(&checked(yaml), &"Home".parse().unwrap()).unwrap();
        let sections: Vec<String> = plan
            .firewall
            .unwrap()
            .rules
            .iter()
            .map(|rule| commands(rule)[0].clone())
            .collect();

        assert_eq!(
            sections,
            [
                "set firewall.spl_rule_in_Laptop_ssh_from_spl_mesh='rule'",
                "set firewall.spl_rule_out_Laptop_ssh_from_lan='rule'",
            ]
        );
    }
}
