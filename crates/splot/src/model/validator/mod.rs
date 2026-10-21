mod endpoints;
mod entities;
mod names;
mod networks;
mod platform;
mod ports;
mod references;
mod services;
mod tags;
pub mod types;
mod unmanaged;
mod wan;

use std::collections::{BTreeMap, HashSet};

use crate::{
    config::Config,
    model::{
        host::{Host, HostRef},
        node::Node,
        service::Service,
        validator::{
            endpoints::check_endpoints, entities::check_entities, names::validate_names,
            networks::check_networks, platform::check_platforms, ports::check_ports,
            services::check_services, tags::validate_tags, types::ValidationReport,
            unmanaged::check_unmanaged, wan::check_wan_zones,
        },
    },
    types::{allow_from_ref::AllowFromRef, identifier::Identifier},
};

/// What the passes built from a config, out of the parts that passed their
/// checks, and what they found.
pub(super) struct Checked {
    pub(super) nodes: BTreeMap<Identifier, Node>,
    pub(super) hosts: Vec<Host>,
    pub(super) services: BTreeMap<HostRef, BTreeMap<Identifier, Service>>,
    pub(super) report: ValidationReport,
}

/// Runs every pass over `config`. The report is in config order.
pub(super) fn check(config: &Config) -> Checked {
    let mut report = ValidationReport::default();

    let platforms = check_platforms(config, &mut report);

    let names = validate_names(config, &mut report);
    let tags = validate_tags(config, &mut report, &names);
    let refs: HashSet<AllowFromRef> = names.into_iter().chain(tags).collect();

    check_entities(config, &mut report);

    let (nodes, hosts) = check_networks(config, &platforms, &mut report);
    check_endpoints(config, &mut report);

    check_ports(config, &mut report);

    let services = check_services(config, &platforms, &hosts, &refs, &mut report);
    check_wan_zones(config, &mut report);

    check_unmanaged(&platforms, &hosts, &services, &mut report);

    // Canonical order for every consumer: by config location, so the output reads
    // top to bottom like the config instead of pass by pass. Stable sort — several
    // diagnostics at one location keep the order their passes produced them in.
    report.sort();

    Checked {
        nodes,
        hosts,
        services,
        report,
    }
}

/// A node with a hub, for the passes' hub tests to build on.
#[cfg(test)]
// Home, in a mesh space with room for hubs. Tests append to it: a hub, other
// nodes, clients.
const HUB_HOME: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1";

#[cfg(test)]
mod tests {
    use crate::{model::validator::HUB_HOME, test_support::report};

    #[test]
    fn shipped_example_config_is_clean() {
        // The example users copy to splot.yml must always validate with no
        // diagnostics, so it can't silently rot as the schema evolves.
        let r = report(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../splot.example.yml"
        )));
        assert!(
            r.errors.is_empty(),
            "splot.example.yml has errors: {:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
        assert!(
            r.warnings.is_empty(),
            "splot.example.yml has warnings: {:?}",
            r.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
    }

    // A minimal config that passes every validator pass with no diagnostics.
    const CLEAN: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
";

    #[test]
    fn validate_config_clean() {
        let r = report(CLEAN);
        assert!(
            r.errors.is_empty(),
            "unexpected errors: {:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
        assert!(
            r.warnings.is_empty(),
            "unexpected warnings: {:?}",
            r.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn report_is_sorted_by_config_location() {
        // The names pass runs before the networks pass, so unsorted the error on
        // Zeta (names) would come before the one on Alpha (networks). Sorted, the
        // report reads top to bottom like the config: Alpha first, then Zeta.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Alpha:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.200.0.1
  Zeta:
    platform:
      os: openwrt
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      Zeta_lan:
        address: 192.168.1.1/24
",
        );
        let paths: Vec<String> = r.errors.iter().map(|e| e.path().to_string()).collect();
        assert_eq!(paths, ["nodes.Alpha.meshIp", "nodes.Zeta.zones.Zeta_lan"]);
    }

    #[test]
    fn hub_config_is_clean_and_its_names_resolve() {
        // `Home.hub`, a hub client by name, the hub's tag and a hub client's tag
        // are all valid references.
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      lan:
        address: 192.168.1.1/24
    hub:
      network: 10.100.49.0/24
      tags: cameras
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          tags: outdoor
          services:
            rtsp:
              port: 554
              proto: tcp
              allowFrom: [Home.lan, Phone]
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.1.10
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: [Home.hub, Home.camera, cameras, outdoor]
"
        ));
        assert!(
            r.errors.is_empty(),
            "unexpected errors: {:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
        assert!(
            r.warnings.is_empty(),
            "unexpected warnings: {:?}",
            r.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
    }
}
