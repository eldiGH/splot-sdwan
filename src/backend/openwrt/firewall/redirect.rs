//! Redirects as uci `redirect` sections.

use crate::{
    backend::openwrt::{
        firewall::FILE as FIREWALL_FILE_NAME,
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    model::host::HostRef,
    plan::firewall::redirect::Redirect,
};

/// The host's part of a redirect's id: a host inside a node with the node's name.
fn host_id(host: &HostRef) -> Vec<&str> {
    match host {
        HostRef::Local { node, name } => vec![node.as_ref(), name.as_ref()],
        _ => vec![host.name().as_ref()],
    }
}

impl UciSection for Redirect {
    const FILE: &'static str = FIREWALL_FILE_NAME;

    fn section_type(&self) -> &str {
        "redirect"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = host_id(&self.host);
        id.push(self.service.as_ref());
        id
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let label = format!("{}_{}", host_id(&self.host).join("_"), self.service);

        section
            .set("name", naming::name_prefixed(&label))
            .set("target", "DNAT")
            .set("src", self.wan_zone.as_ref())
            .set("src_dport", self.external_port.to_string())
            .extend_list("src_ip", &self.sources)
            .set("dest", self.dest_zone.to_string())
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", self.internal_port.to_string())
            .extend_list("proto", &self.proto)
    }
}
