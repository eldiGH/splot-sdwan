//! DNS from the nodes that forward the node's domain to it, as uci `rule`
//! sections: one to the node itself, and one into the zone its DNS address is
//! on (whichever it turns out to be, the other never matches).

use super::zone_name;
use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    plan::firewall::{DnsIn, zone_ref::ZoneRef},
};

/// The rule to the node itself, or into `zone`.
pub(super) struct DnsRule<'a> {
    pub(super) dns: &'a DnsIn,
    pub(super) zone: Option<&'a ZoneRef>,
}

impl UciSection for DnsRule<'_> {
    fn section_type(&self) -> &str {
        "rule"
    }

    /// Not a service's: their ids begin with their direction.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = vec!["dns"];
        id.extend(self.zone.map(zone_name));
        id
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let label = match self.zone {
            Some(zone) => format!("DNS from the nodes that forward to it, to {zone}"),
            None => "DNS from the nodes that forward to it".to_owned(),
        };
        section
            .set("name", naming::name_prefixed(&label))
            .set("src", zone_name(&ZoneRef::Mesh))
            .set_if_some("dest", self.zone.map(zone_name))
            .set("family", "ipv4")
            .extend_list("proto", ["tcp", "udp"])
            .extend_list("src_ip", self.dns.from.iter().map(|(_, address)| address))
            .extend_list("dest_ip", [self.dns.address])
            .set("dest_port", "53")
            .set("target", "ACCEPT")
    }
}

/// The rule to the node, and the one into the zone the address is on.
pub(super) fn rules(dns: &DnsIn) -> Vec<DnsRule<'_>> {
    std::iter::once(None)
        .chain(dns.zone.as_ref().map(Some))
        .map(|zone| DnsRule { dns, zone })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(dns: &DnsIn) -> Vec<String> {
        rules(dns)
            .iter()
            .flat_map(|rule| rule.to_section().commands("firewall"))
            .map(|command| command.to_string())
            .collect()
    }

    #[test]
    fn dns_from_the_forwarders_to_the_address_as_the_node_and_into_its_zone() {
        let dns = DnsIn {
            address: "192.168.1.53".parse().unwrap(),
            zone: Some(ZoneRef::Named("lan".parse().unwrap())),
            from: vec![
                ("Cabin".parse().unwrap(), "10.100.0.2".parse().unwrap()),
                ("Barn".parse().unwrap(), "10.100.0.4".parse().unwrap()),
            ],
        };
        assert_eq!(
            commands(&dns),
            [
                "set firewall.spl_rule_dns='rule'",
                "set firewall.spl_rule_dns.name='[SPLOT] DNS from the nodes that forward to it'",
                "set firewall.spl_rule_dns.src='spl_mesh'",
                "set firewall.spl_rule_dns.family='ipv4'",
                "add_list firewall.spl_rule_dns.proto='tcp'",
                "add_list firewall.spl_rule_dns.proto='udp'",
                "add_list firewall.spl_rule_dns.src_ip='10.100.0.2'",
                "add_list firewall.spl_rule_dns.src_ip='10.100.0.4'",
                "add_list firewall.spl_rule_dns.dest_ip='192.168.1.53'",
                "set firewall.spl_rule_dns.dest_port='53'",
                "set firewall.spl_rule_dns.target='ACCEPT'",
                "set firewall.spl_rule_dns_lan='rule'",
                "set firewall.spl_rule_dns_lan.name='[SPLOT] DNS from the nodes that forward to it, to lan'",
                "set firewall.spl_rule_dns_lan.src='spl_mesh'",
                "set firewall.spl_rule_dns_lan.dest='lan'",
                "set firewall.spl_rule_dns_lan.family='ipv4'",
                "add_list firewall.spl_rule_dns_lan.proto='tcp'",
                "add_list firewall.spl_rule_dns_lan.proto='udp'",
                "add_list firewall.spl_rule_dns_lan.src_ip='10.100.0.2'",
                "add_list firewall.spl_rule_dns_lan.src_ip='10.100.0.4'",
                "add_list firewall.spl_rule_dns_lan.dest_ip='192.168.1.53'",
                "set firewall.spl_rule_dns_lan.dest_port='53'",
                "set firewall.spl_rule_dns_lan.target='ACCEPT'",
            ]
        );

        // At its mesh IP: the node's own, no zone.
        let at_mesh_ip = DnsIn { zone: None, ..dns };
        assert!(
            !commands(&at_mesh_ip)
                .iter()
                .any(|command| command.contains("dest="))
        );
    }
}
