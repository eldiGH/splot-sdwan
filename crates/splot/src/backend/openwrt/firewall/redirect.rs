//! Redirects as uci `redirect` sections.

use super::{qualified_host_id, zone_name};
use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    plan::firewall::redirect::Redirect,
    types::ip::Ipv4Network,
};

/// A port forward from one of its WAN sources, or from anywhere when it has
/// none.
pub(super) struct RedirectFrom<'a> {
    redirect: &'a Redirect,
    /// The source, and its part of the section id.
    source: Option<(&'a Ipv4Network, String)>,
}

/// A redirect for each of the forward's WAN sources, or one from anywhere when
/// it has none. fw4 takes a single `src_ip` on a redirect, and skips one that
/// has a list. Its NAT reflection doesn't read `src_ip`, so fw4 repeats the
/// same reflection rules for each source, which does no harm.
pub(super) fn per_source(redirect: &Redirect) -> Vec<RedirectFrom<'_>> {
    if redirect.sources.is_empty() {
        return vec![RedirectFrom {
            redirect,
            source: None,
        }];
    }

    redirect
        .sources
        .iter()
        .map(|source| RedirectFrom {
            redirect,
            source: Some((source, source_id(source))),
        })
        .collect()
}

/// A source as a part of a section id, which takes no `.` or `/`:
/// `198.51.100.0/24` is `198_51_100_0_24`. Every source is four octets and a
/// prefix, so two sources can't give the same id.
fn source_id(source: &Ipv4Network) -> String {
    source.to_string().replace(['.', '/'], "_")
}

impl UciSection for RedirectFrom<'_> {
    fn section_type(&self) -> &str {
        "redirect"
    }

    /// The source is part of the id: adding one to a forward adds a section and
    /// leaves the others as they are.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let mut id = qualified_host_id(&self.redirect.host);
        id.push(self.redirect.service.as_ref());
        id.extend(self.source.as_ref().map(|(_, id)| id.as_str()));
        id
    }

    /// The label is in the config's notation: `[SPLOT] Home.nas https`, and
    /// `[SPLOT] Home.nas https from 198.51.100.0/24` from one source.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let redirect = self.redirect;
        let source = self.source.as_ref().map(|(source, _)| source.to_string());
        let label = match &source {
            Some(source) => format!("{} {} from {source}", redirect.host, redirect.service),
            None => format!("{} {}", redirect.host, redirect.service),
        };

        section
            .set("name", naming::name_prefixed(&label))
            .set("target", "DNAT")
            .set("src", redirect.wan_zone.as_ref())
            .set("src_dport", redirect.external_port.to_string())
            .set_if_some("src_ip", source)
            .set("dest", zone_name(&redirect.dest_zone))
            .set("dest_ip", redirect.dest_ip.to_string())
            .set("dest_port", redirect.internal_port.to_string())
            .extend_list("proto", &redirect.proto)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        model::host::HostRef, plan::firewall::zone_ref::ZoneRef, types::protocol::Protocol,
    };

    /// Home.nas's https, forwarded from `sources`.
    fn redirect(sources: &[&str]) -> Redirect {
        Redirect {
            host: HostRef::Local {
                node: "Home".parse().unwrap(),
                name: "nas".parse().unwrap(),
            },
            service: "https".parse().unwrap(),
            wan_zone: "wan".parse().unwrap(),
            external_port: "8443".parse().unwrap(),
            sources: sources
                .iter()
                .map(|source| source.parse().unwrap())
                .collect(),
            dest_zone: ZoneRef::Named("lan".parse().unwrap()),
            dest_ip: "192.168.1.20".parse().unwrap(),
            internal_port: "443".parse().unwrap(),
            proto: BTreeSet::from([Protocol::Tcp]),
        }
    }

    /// The uci commands of each section `redirect` renders as.
    fn rendered(redirect: &Redirect) -> Vec<Vec<String>> {
        per_source(redirect)
            .iter()
            .map(|section| {
                section
                    .to_section()
                    .commands("firewall")
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn a_redirect_is_labelled_in_config_notation() {
        let rendered = rendered(&redirect(&[]));
        let [commands] = rendered.as_slice() else {
            panic!("expected one redirect, got {rendered:?}");
        };

        assert!(
            commands.contains(
                &"set firewall.spl_redirect_Home_nas_https.name='[SPLOT] Home.nas https'"
                    .to_owned()
            ),
            "{commands:?}"
        );
    }

    #[test]
    fn a_forward_from_anywhere_is_one_redirect_without_a_source() {
        let rendered = rendered(&redirect(&[]));
        let [commands] = rendered.as_slice() else {
            panic!("expected one redirect, got {rendered:?}");
        };

        assert_eq!(
            commands[0],
            "set firewall.spl_redirect_Home_nas_https='redirect'"
        );
        assert!(
            !commands.iter().any(|command| command.contains(".src_ip")),
            "{commands:?}"
        );
    }

    #[test]
    fn one_source_is_one_src_ip_not_a_list() {
        // fw4 skips a redirect whose src_ip is a list, even a list of one.
        let rendered = rendered(&redirect(&["198.51.100.0/24"]));
        let [commands] = rendered.as_slice() else {
            panic!("expected one redirect, got {rendered:?}");
        };
        let section = "firewall.spl_redirect_Home_nas_https_198_51_100_0_24";

        assert_eq!(commands[0], format!("set {section}='redirect'"));
        assert!(
            commands.contains(&format!("set {section}.src_ip='198.51.100.0/24'")),
            "{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.starts_with("add_list") && command.contains(".src_ip")),
            "{commands:?}"
        );
    }

    #[test]
    fn each_source_has_a_redirect_of_its_own() {
        let rendered = rendered(&redirect(&["198.51.100.0/24", "203.0.113.7/32"]));
        assert_eq!(rendered.len(), 2, "{rendered:?}");

        for (id, source) in [
            ("198_51_100_0_24", "198.51.100.0/24"),
            ("203_0_113_7_32", "203.0.113.7/32"),
        ] {
            let section = format!("firewall.spl_redirect_Home_nas_https_{id}");
            let Some(commands) = rendered
                .iter()
                .find(|commands| commands[0] == format!("set {section}='redirect'"))
            else {
                panic!("no redirect {section} in {rendered:?}");
            };

            assert!(
                commands.contains(&format!("set {section}.src_ip='{source}'")),
                "{commands:?}"
            );
            assert!(
                commands.contains(&format!(
                    "set {section}.name='[SPLOT] Home.nas https from {source}'"
                )),
                "{commands:?}"
            );
            assert_eq!(
                commands
                    .iter()
                    .filter(|command| command.contains(".src_ip"))
                    .count(),
                1,
                "{commands:?}"
            );
        }
    }
}
