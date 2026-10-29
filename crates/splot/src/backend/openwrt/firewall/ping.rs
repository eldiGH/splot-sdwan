//! The peers' ping as a uci `rule` section.

use super::zone_name;
use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    plan::firewall::{Ping, zone_ref::ZoneRef},
};

impl UciSection for Ping {
    fn section_type(&self) -> &str {
        "rule"
    }

    /// Not a service's: their ids begin with their direction.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        ["ping"]
    }

    /// To the node itself (no `dest`), from the peers' own addresses only: all
    /// of them arrive over the mesh.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed("ping from its peers"))
            .set("src", zone_name(&ZoneRef::Mesh))
            .set("family", "ipv4")
            .set("proto", "icmp")
            .extend_list("icmp_type", ["echo-request"])
            .extend_list("src_ip", self.from.iter().map(|(_, address)| address))
            .extend_list("dest_ip", [self.to])
            .set("target", "ACCEPT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::host::HostRef, plan::firewall::Ping};

    #[test]
    fn the_peers_may_ping_the_node_and_nothing_else() {
        let ping = Ping {
            to: "10.100.0.1".parse().unwrap(),
            from: vec![
                (
                    HostRef::Node("Cabin".parse().unwrap()),
                    "10.100.0.2".parse().unwrap(),
                ),
                (
                    HostRef::Client("Phone".parse().unwrap()),
                    "10.100.1.10".parse().unwrap(),
                ),
            ],
        };
        let commands: Vec<String> = ping
            .to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            commands,
            [
                "set firewall.spl_rule_ping='rule'",
                "set firewall.spl_rule_ping.name='[SPLOT] ping from its peers'",
                "set firewall.spl_rule_ping.src='spl_mesh'",
                "set firewall.spl_rule_ping.family='ipv4'",
                "set firewall.spl_rule_ping.proto='icmp'",
                "add_list firewall.spl_rule_ping.icmp_type='echo-request'",
                "add_list firewall.spl_rule_ping.src_ip='10.100.0.2'",
                "add_list firewall.spl_rule_ping.src_ip='10.100.1.10'",
                "add_list firewall.spl_rule_ping.dest_ip='10.100.0.1'",
                "set firewall.spl_rule_ping.target='ACCEPT'",
            ]
        );
    }
}
