mod listen_port;
mod ping;
mod redirect;
mod rules;
mod zones;

use log::{Level, debug, info, log_enabled};

use super::{
    naming,
    section::{Section, UciSection},
};
use crate::{
    model::host::HostRef,
    plan::firewall::{FirewallPlan, Verdict, zone_ref::ZoneRef},
};
use zones::MeshZone;

pub(super) const FILE: &str = "firewall";

/// A host's part of a section id, with its node's name when it's inside a node,
/// so it can't clash with another node's host of the same name.
fn qualified_host_id(host: &HostRef) -> Vec<&str> {
    match host {
        HostRef::Local { node, name } => vec![node.as_ref(), name.as_ref()],
        _ => vec![host.name().as_ref()],
    }
}

/// A zone as fw4 knows it, by its `name`: splot's mesh zone after the interface
/// it covers, one of the operator's by its key in `splot.yml`.
fn zone_name(zone: &ZoneRef) -> String {
    match zone {
        ZoneRef::Mesh => naming::mesh_interface().to_string(),
        ZoneRef::Named(zone) => zone.to_string(),
    }
}

/// A verdict as fw4 spells it.
fn target(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "ACCEPT",
        Verdict::Drop => "DROP",
    }
}

/// The plan's firewall section as the `firewall` file's sections: the mesh zone,
/// the peers' ping and the listen port (if any), then the rules, then the
/// redirects.
pub(super) fn render(firewall: &FirewallPlan) -> Vec<Section> {
    info!("Generating firewall config");
    info!(
        "  {} rule(s), {} redirect(s)",
        firewall.rules.len(),
        firewall.redirects.len()
    );

    if log_enabled!(Level::Debug) {
        for rule in &firewall.rules {
            debug!("  {rule}");
        }
        for redirect in &firewall.redirects {
            debug!("  {redirect}");
        }
    }

    let zone = firewall
        .mesh_zone
        .as_ref()
        .map(|policy| MeshZone(policy).to_section());
    let ping = firewall.ping.as_ref().map(|ping| ping.to_section());
    let listen_port = firewall
        .listen_port
        .as_ref()
        .map(|listen_port| listen_port.to_section());
    let rules = firewall.rules.iter().map(|rule| rule.to_section());
    let redirects = firewall
        .redirects
        .iter()
        .map(|redirect| redirect.to_section());

    zone.into_iter()
        .chain(ping)
        .chain(listen_port)
        .chain(rules)
        .chain(redirects)
        .collect()
}

#[cfg(test)]
mod tests {
    use splot_core::uci::section::Value;

    use super::*;
    use crate::{plan, test_support::checked};

    /// The value of `option` in each of `sections` of type `section_type`.
    fn values<'a>(sections: &'a [Section], section_type: &str, option: &str) -> Vec<&'a str> {
        sections
            .iter()
            .filter(|section| section.section_type == section_type)
            .flat_map(|section| &section.options)
            .filter_map(|(name, value)| match value {
                Value::Single(value) if name == option => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_redirect_into_the_mesh_names_the_mesh_zone_as_fw4_knows_it() {
        // fw4 knows a zone by its `name`: a redirect naming any other resolves to
        // nothing. The camera on Home's hub is reached over the mesh.
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp: { port: 554, proto: tcp, wan: { via: Home } }
",
        );
        let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
        let sections = render(&plan.firewall.unwrap());

        assert_eq!(values(&sections, "zone", "name"), ["spl_mesh"]);
        assert_eq!(values(&sections, "redirect", "dest"), ["spl_mesh"]);
    }
}
