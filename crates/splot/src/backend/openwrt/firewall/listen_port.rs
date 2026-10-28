//! The WireGuard listen port, let in from the WAN, as a uci `rule` section.

use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    plan::firewall::ListenPort,
};

impl UciSection for ListenPort {
    fn section_type(&self) -> &str {
        "rule"
    }

    /// Not a service's: their ids begin with their direction.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        ["listen_port"]
    }

    /// To the node itself (no `dest`), from anywhere on its WAN: WireGuard
    /// answers only a peer whose key it has. Either family, whichever a peer
    /// dials by.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed("WireGuard listen port"))
            .set("src", self.wan_zone.as_ref())
            .set("proto", "udp")
            .set("dest_port", self.port.to_string())
            .set("target", "ACCEPT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listen_port_is_let_in_from_the_wan_to_the_node() {
        let listen_port = ListenPort {
            wan_zone: "wan".parse().unwrap(),
            port: "51820".parse().unwrap(),
        };
        let commands: Vec<String> = listen_port
            .to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            commands,
            [
                "set firewall.spl_rule_listen_port='rule'",
                "set firewall.spl_rule_listen_port.name='[SPLOT] WireGuard listen port'",
                "set firewall.spl_rule_listen_port.src='wan'",
                "set firewall.spl_rule_listen_port.proto='udp'",
                "set firewall.spl_rule_listen_port.dest_port='51820'",
                "set firewall.spl_rule_listen_port.target='ACCEPT'",
            ]
        );
    }
}
