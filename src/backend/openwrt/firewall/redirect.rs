//! Redirects as uci `redirect` sections.

use crate::{
    backend::openwrt::{
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
    fn section_type(&self) -> &str {
        "redirect"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = host_id(&self.host);
        id.push(self.service.as_ref());
        id
    }

    /// The label is in the config's notation: `[SPLOT] Home.nas https`.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let label = format!("{} {}", self.host, self.service);

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{protocol::Protocol, types::zone_ref::ZoneRef};

    #[test]
    fn a_redirect_is_labelled_in_config_notation() {
        let redirect = Redirect {
            host: HostRef::Local {
                node: "Home".parse().unwrap(),
                name: "nas".parse().unwrap(),
            },
            service: "https".parse().unwrap(),
            wan_zone: "wan".parse().unwrap(),
            external_port: "8443".parse().unwrap(),
            sources: Vec::new(),
            dest_zone: ZoneRef::Named("lan".parse().unwrap()),
            dest_ip: "192.168.1.20".parse().unwrap(),
            internal_port: "443".parse().unwrap(),
            proto: BTreeSet::from([Protocol::Tcp]),
        };
        let commands: Vec<String> = redirect
            .to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert!(
            commands.contains(
                &"set firewall.spl_redirect_Home_nas_https.name='[SPLOT] Home.nas https'"
                    .to_owned()
            ),
            "{commands:?}"
        );
    }
}
