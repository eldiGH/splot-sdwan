//! The node's DNS as dnsmasq on OpenWrt reads it: its names as sections of
//! splot's own in the `dhcp` file (`hostrecord`, an address and its reverse;
//! `cname`, an alias), and its forwarding as values in the operator's dnsmasq
//! sections, the only place dnsmasq on OpenWrt reads them from.

use splot_core::protocol::openwrt::DnsmasqValues;

use super::section::{Section, UciSection, UciSectionBuilder};
use crate::plan::dns::{Alias, DnsPlan, Record};

/// The section types splot owns in the `dhcp` file for the DNS.
pub(super) const TYPES: [&str; 2] = ["hostrecord", "cname"];

impl UciSection for Record {
    fn section_type(&self) -> &str {
        TYPES[0]
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.host.name().as_ref()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", self.name.to_string())
            .set("ip", self.ip.to_string())
    }
}

impl UciSection for Alias {
    fn section_type(&self) -> &str {
        TYPES[1]
    }

    /// Its name: unique in the domain.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.name.as_ref().split('.').next().unwrap_or_default()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("cname", self.name.to_string())
            .set("target", self.target.to_string())
    }
}

/// The names, as the `dhcp` file's sections.
pub(super) fn render(dns: &DnsPlan) -> Vec<Section> {
    dns.records
        .iter()
        .map(UciSection::to_section)
        .chain(dns.aliases.iter().map(UciSection::to_section))
        .collect()
}

/// What the operator's dnsmasq sections hold for splot: its own domain answered
/// there alone, the others' forwarded, endpoint names sent to public DNS; and
/// the forwarded domains allowed private answers (OpenWrt's rebind protection
/// drops them otherwise).
pub(super) fn values(dns: &DnsPlan) -> DnsmasqValues {
    let local = dns.local.iter().map(|domain| format!("/{domain}/"));
    let forwards = dns
        .forwards
        .iter()
        .map(|forward| format!("/{}/{}", forward.domain, forward.address));
    let public = dns.public.iter().map(|name| format!("/{name}/#"));

    DnsmasqValues {
        server: local.chain(forwards).chain(public).collect(),
        rebind_domain: dns
            .forwards
            .iter()
            .map(|forward| forward.domain.to_string())
            .collect(),
        domains: dns
            .local
            .iter()
            .chain(dns.forwards.iter().map(|forward| &forward.domain))
            .map(ToString::to_string)
            .collect(),
    }
}
