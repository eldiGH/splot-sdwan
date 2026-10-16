//! Rules as uci `rule` sections.

use crate::{
    backend::openwrt::{
        firewall::FILE as FIREWALL_FILE_NAME,
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    model::host::HostRef,
    plan::firewall::rules::{Direction, Rule},
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
    match (host, direction) {
        (HostRef::Local { node, name }, Direction::Egress) => vec![node.as_ref(), name.as_ref()],
        _ => vec![host.name().as_ref()],
    }
}

impl UciSection for Rule {
    const FILE: &'static str = FIREWALL_FILE_NAME;

    fn section_type(&self) -> &str {
        "rule"
    }

    /// The direction is part of the id: one service can need an ingress and an
    /// egress rule on the same node (a global client with IPs on two nodes).
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = vec![direction(self.direction)];
        id.extend(host_id(&self.host, self.direction));
        id.push(self.service.as_ref());
        id
    }

    /// The label is in the config's notation, so what LuCI shows can be searched
    /// for in `splot.yml`: `[SPLOT] out: Cabin.camera rtsp`.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let label = format!(
            "{}: {} {}",
            direction(self.direction),
            self.host,
            self.service
        );

        section
            .set("name", naming::name_prefixed(&label))
            .set("src", "*")
            .set("dest", "*")
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
    use crate::{plan, test_support::checked};

    fn camera_rule(direction: Direction) -> Rule {
        Rule {
            host: HostRef::Local {
                node: "Cabin".parse().unwrap(),
                name: "camera".parse().unwrap(),
            },
            service: "rtsp".parse().unwrap(),
            direction,
            sources: vec!["192.168.1.0/24".parse().unwrap()],
            destinations: vec!["192.168.2.30/32".parse().unwrap()],
            port: "554".parse().unwrap(),
            proto: BTreeSet::from([crate::protocol::Protocol::Tcp]),
        }
    }

    /// A rendered rule's `name` option.
    fn label(rule: &Rule) -> String {
        rule.to_uci_commands()
            .iter()
            .map(ToString::to_string)
            .find(|command| command.contains(".name="))
            .unwrap()
    }

    #[test]
    fn a_rule_is_labelled_in_config_notation_with_its_direction() {
        // What LuCI shows can be searched for in splot.yml; the section names keep
        // uci's character set.
        assert_eq!(
            label(&camera_rule(Direction::Egress)),
            "set firewall.spl_rule_out_Cabin_camera_rtsp.name='[SPLOT] out: Cabin.camera rtsp'"
        );
        assert_eq!(
            label(&camera_rule(Direction::Ingress)),
            "set firewall.spl_rule_in_camera_rtsp.name='[SPLOT] in: Cabin.camera rtsp'"
        );
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
        let plan = plan::plan(&checked(yaml), &"Home".parse().unwrap()).unwrap();
        let sections: Vec<String> = plan
            .firewall
            .rules
            .iter()
            .map(|rule| rule.to_uci_commands()[0].to_string())
            .collect();

        let laptop_in = "set firewall.spl_rule_in_Laptop_ssh='rule'".to_owned();
        let laptop_out = "set firewall.spl_rule_out_Laptop_ssh='rule'".to_owned();
        assert!(sections.contains(&laptop_in), "{sections:?}");
        assert!(sections.contains(&laptop_out), "{sections:?}");
    }
}
