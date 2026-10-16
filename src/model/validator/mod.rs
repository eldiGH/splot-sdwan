mod entities;
mod names;
mod networks;
mod ports;
mod references;
mod services;
mod tags;
pub mod types;
mod wan;

use std::collections::{BTreeMap, HashSet};

use crate::{
    config::Config,
    model::{
        host::{Host, HostRef},
        service::Service,
        validator::{
            entities::check_entities, names::validate_names, networks::check_networks,
            ports::check_ports, services::check_services, tags::validate_tags,
            types::ValidationReport, wan::check_wan_zones,
        },
    },
    types::{allow_from_ref::AllowFromRef, identifier::Identifier},
};

/// What the passes built from a config, out of the parts that passed their
/// checks, and what they found.
pub(super) struct Checked {
    pub(super) hosts: Vec<Host>,
    pub(super) services: BTreeMap<HostRef, BTreeMap<Identifier, Service>>,
    pub(super) report: ValidationReport,
}

/// Runs every pass over `config`. The report is in config order.
pub(super) fn check(config: &Config) -> Checked {
    let mut report = ValidationReport::default();

    let names = validate_names(config, &mut report);
    let tags = validate_tags(config, &mut report, &names);
    let refs: HashSet<AllowFromRef> = names.into_iter().chain(tags).collect();

    check_entities(config, &mut report);

    let hosts = check_networks(config, &mut report);

    check_ports(config, &mut report);

    let services = check_services(config, &hosts, &refs, &mut report);
    check_wan_zones(config, &mut report);

    // Canonical order for every consumer: by config location, so the output reads
    // top to bottom like the config instead of pass by pass. Stable sort — several
    // diagnostics at one location keep the order their passes produced them in.
    report.sort();

    Checked {
        hosts,
        services,
        report,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::{ValidationError, ValidationReport, ValidationWarning},
        test_support::{error_at, has_error, has_warning, report, warning_at},
        types::ip::ReservedAddress,
    };

    #[test]
    fn shipped_example_config_is_clean() {
        // The example users copy to splot.yml must always validate with no
        // diagnostics, so it can't silently rot as the schema evolves.
        let r = report(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
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
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.200.0.1
  Zeta:
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

    // ── names ──────────────────────────────────────────────────────────────

    #[test]
    fn names_global_name_collision() {
        // Node and client share the name "Phone".
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Phone:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::GlobalNameCollision { name, .. } if name == "Phone")
        ));
    }

    #[test]
    fn names_local_name_collision() {
        // Zone "printer" and device "printer" in the same node share a local name.
        let r = report(
            "
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
      printer:
        address: 192.168.2.1/24
        devices:
          printer:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:FF
",
        );
        // The device "printer" (inside zone "printer") is the second use of the
        // name, so it's the one flagged — at its own nested location.
        assert!(error_at(
            &r,
            "nodes.Home.zones.printer.devices.printer",
            |e| matches!(e, ValidationError::LocalNameCollision { name, .. } if name == "printer")
        ));
    }

    #[test]
    fn names_local_shadows_global() {
        // Global client "Phone"; a device in Home is also named "Phone".
        let r = report(
            "
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
        devices:
          Phone:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Phone")
        ));
    }

    // A local name equal to another node's name must be flagged no matter how the
    // two names sort. Nodes are walked in sorted order, so the two tests below put
    // the shadowed node before and after the node holding the local name.

    #[test]
    fn names_local_shadows_node_sorting_before() {
        // Device "Cabin" on node "Home"; node "Cabin" sorts before "Home".
        let r = report(
            "
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
        devices:
          Cabin:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:FF
  Cabin:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.zones.lan.devices.Cabin",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Cabin")
        ));
    }

    #[test]
    fn names_local_shadows_node_sorting_after() {
        // Device "Zeta" on node "Alpha"; node "Zeta" sorts after "Alpha", so it has
        // not been registered yet when Alpha's local names are checked — unless all
        // global names are collected first.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Alpha:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          Zeta:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:FF
  Zeta:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        assert!(error_at(
            &r,
            "nodes.Alpha.zones.lan.devices.Zeta",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Zeta")
        ));
    }

    #[test]
    fn names_invalid_prefix() {
        // Zone "Home_lan" starts with the reserved prefix "Home_" (node "Home" exists).
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      Home_lan:
        address: 192.168.1.1/24
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::InvalidPrefix { name, .. } if name == "Home_lan")
        ));
    }

    #[test]
    fn names_same_local_across_nodes_is_ok() {
        // Both Home and Cabin can have a zone named "lan" — local names don't collide cross-node.
        let r = report(
            "
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
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::LocalNameCollision { .. }
        )));
    }

    // ── tags ───────────────────────────────────────────────────────────────

    #[test]
    fn tags_collision_with_node_name() {
        // Tag "Home" on Phone collides with node name "Home".
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    tags: Home
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::TagWithNameCollision { tag, .. } if tag == "Home")
        ));
    }

    #[test]
    fn tags_same_tag_multiple_places_ok() {
        // Tag "admin" applied to both Phone and Home's zone — no error.
        let r = report(
            "
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
        tags: admin
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.0.100
    tags: admin
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::TagWithNameCollision { .. }
        )));
    }

    // ── references ─────────────────────────────────────────────────────────

    #[test]
    fn refs_unknown_allowfrom() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: NoSuchThing
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::UnknownRef { .. }
        )));
    }

    #[test]
    fn refs_self_node_always_valid() {
        // $node is always in the known-references set; no UnknownRef.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: \"$node\"
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::UnknownRef { .. }
        )));
    }

    #[test]
    fn refs_unreachable_service_warning() {
        // Service with neither allowFrom nor wan.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ghost:
        port: 9999
        proto: tcp
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnreachableService { .. }
        )));
    }

    #[test]
    fn refs_wan_only_service_no_unreachable_warning() {
        // wan-only service (no allowFrom) must not produce UnreachableService.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(!has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnreachableService { .. }
        )));
    }

    // ── entities ───────────────────────────────────────────────────────────

    #[test]
    fn entities_mac_missing() {
        // Client with a zone IP but no macs.
        let r = report(
            "
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
clients:
  Phone:
    ips:
      Home:
        lan: 192.168.1.50
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::MacMissing { .. }
        )));
    }

    #[test]
    fn entities_unused_mac_warning() {
        // Client with macs but no zone IPs.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedMac { .. }
        )));
    }

    #[test]
    fn entities_public_key_missing_for_mesh() {
        // Client with meshIp but no publicKey.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PublicKeyMissing { .. }
        )));
    }

    #[test]
    fn entities_unused_public_key_warning() {
        // Client with publicKey but no meshIp.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Orphan:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedPublicKey { .. }
        )));
    }

    #[test]
    fn entities_unreachable_client_warning() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Ghost: {}
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnreachableClient { .. }
        )));
    }

    #[test]
    fn entities_node_missing() {
        // client.ips references a node that does not exist in nodes.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    ips:
      NoSuchNode:
        lan: 192.168.1.50
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::NodeMissing { node_name, .. } if node_name == "NoSuchNode")
        ));
    }

    #[test]
    fn entities_node_network_missing() {
        // client.ips.Home references "guest" but Home has no "guest" network.
        let r = report(
            "
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
clients:
  Phone:
    ips:
      Home:
        guest: 192.168.99.50
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::NodeNetworkMissing { network_name, .. } if network_name == "guest")
        ));
    }

    // Every node and global client needs its own public key: two nodes
    // sharing one make "which node am I" ambiguous, and WireGuard can't have two
    // peers with the same key on one interface. The later occurrence is flagged.

    #[test]
    fn entities_duplicate_public_key_between_nodes() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
",
        );
        // Cabin sorts first, so Home's key is the duplicate.
        assert!(error_at(&r, "nodes.Home.publicKey", |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Cabin.publicKey"
        )));
    }

    #[test]
    fn entities_duplicate_public_key_node_and_global_client() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    meshIp: 10.100.0.100
",
        );
        assert!(error_at(&r, "clients.Phone.publicKey", |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { with, .. }
                if with.to_string() == "nodes.Home.publicKey"
        )));
    }

    #[test]
    fn entities_distinct_public_keys_are_fine() {
        // Same shape as above, every key distinct: no duplicate error.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.0.100
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::DuplicatePublicKey { .. }
        )));
    }

    // ── networks ───────────────────────────────────────────────────────────

    #[test]
    fn networks_collision_mesh_and_zone_overlap() {
        // Zone 192.168.1.0/24 overlaps with meshNetwork 192.168.1.0/24.
        let r = report(
            "
meshNetwork: 192.168.1.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 192.168.1.1
    zones:
      lan:
        address: 192.168.1.2/24
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    #[test]
    fn networks_collision_zone_zone() {
        // Two zones with the same subnet.
        let r = report(
            "
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
        address: 192.168.1.1/24
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    #[test]
    fn networks_ip_outside_mesh_subnet() {
        // Node meshIp 10.200.0.1 is outside meshNetwork 10.100.0.0/24.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.200.0.1
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::IpOutsideSubnet { .. }
        )));
    }

    #[test]
    fn networks_ip_outside_zone_subnet() {
        // Device IP 192.168.2.50 is outside its zone 192.168.1.0/24.
        let r = report(
            "
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
        devices:
          printer:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:FF
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.zones.lan.devices.printer.ip",
            |e| matches!(e, ValidationError::IpOutsideSubnet { .. })
        ));
    }

    #[test]
    fn networks_ip_collision_two_nodes_same_mesh_ip() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::IpCollision { .. }
        )));
    }

    #[test]
    fn networks_client_many_zones() {
        // Client with IPs on two zone networks of the same node (max one allowed).
        let r = report(
            "
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
      guest:
        address: 192.168.2.1/24
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
        guest: 192.168.2.50
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::NodeClientManyZones { .. }
        )));
    }

    // A host IP must not be its subnet's network or broadcast address. Such an IP
    // used to pass validation and then panic in the generators. The fixture puts
    // all five kinds of host IP on reserved addresses; the two tests swap which
    // ones get the network address and which the broadcast address.

    fn reserved_fixture(
        node_mesh_ip: &str,
        client_mesh_ip: &str,
        device_ip: &str,
        hub_client_ip: &str,
        client_zone_ip: &str,
    ) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: {node_mesh_ip}
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: {device_ip}
            macs: AA:BB:CC:DD:EE:01
      iot:
        address: 192.168.2.1/24
    hub:
      network: 10.100.0.128/26
      clients:
        camera:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: {hub_client_ip}
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: {client_mesh_ip}
    macs: AA:BB:CC:DD:EE:02
    ips:
      Home:
        iot: {client_zone_ip}
"
        )
    }

    fn reserved_at(r: &ValidationReport, path: &str, expected: ReservedAddress) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::ReservedHostAddress { kind, .. } if *kind == expected),
        )
    }

    const NODE_MESH_IP: &str = "nodes.Home.meshIp";
    const CLIENT_MESH_IP: &str = "clients.Phone.meshIp";
    const DEVICE_IP: &str = "nodes.Home.zones.lan.devices.printer.ip";
    const HUB_CLIENT_IP: &str = "nodes.Home.hub.clients.camera.ip";
    const CLIENT_ZONE_IP: &str = "clients.Phone.ips.Home.iot";

    #[test]
    fn networks_host_ip_on_network_address() {
        let r = report(&reserved_fixture(
            "10.100.0.0",
            "10.100.0.255",
            "192.168.1.0",
            "10.100.0.128",
            "192.168.2.0",
        ));
        assert!(reserved_at(&r, NODE_MESH_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, CLIENT_MESH_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, DEVICE_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, HUB_CLIENT_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, CLIENT_ZONE_IP, ReservedAddress::Network));
    }

    #[test]
    fn networks_host_ip_on_broadcast_address() {
        let r = report(&reserved_fixture(
            "10.100.0.255",
            "10.100.0.0",
            "192.168.1.255",
            "10.100.0.191",
            "192.168.2.255",
        ));
        assert!(reserved_at(&r, NODE_MESH_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, CLIENT_MESH_IP, ReservedAddress::Network));
        assert!(reserved_at(&r, DEVICE_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, HUB_CLIENT_IP, ReservedAddress::Broadcast));
        assert!(reserved_at(&r, CLIENT_ZONE_IP, ReservedAddress::Broadcast));
    }

    #[test]
    fn networks_host_ips_ordinary_addresses_are_fine() {
        // Same fixture, every IP an ordinary host address: no reserved-address error.
        let r = report(&reserved_fixture(
            "10.100.0.1",
            "10.100.0.100",
            "192.168.1.50",
            "10.100.0.130",
            "192.168.2.60",
        ));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::ReservedHostAddress { .. }
        )));
    }

    #[test]
    fn networks_slash_31_has_no_reserved_addresses() {
        // RFC 3021: both addresses of a /31 are usable host addresses.
        let r = report(
            "
meshNetwork: 10.100.0.0/31
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.0
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        assert!(
            r.errors.is_empty(),
            "unexpected errors: {:?}",
            r.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
    }

    // ── ports ──────────────────────────────────────────────────────────────

    #[test]
    fn ports_internal_collision_two_node_services() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: \"$node\"
      ssh2:
        port: 22
        proto: tcp
        allowFrom: \"$node\"
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_tcp_and_udp_same_number_ok() {
        // TCP 80 and UDP 80 on the same node don't collide.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        allowFrom: \"$node\"
      dns:
        port: 80
        proto: udp
        allowFrom: \"$node\"
",
        );
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_external_collision() {
        // Two services both exposed externally on port 80/tcp via the same node.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      http1:
        port: 80
        proto: tcp
        wan:
          via: Home
      http2:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    #[test]
    fn ports_node_listen_port_vs_external_udp_service() {
        // A UDP service exposed on the same external port as the node's WG listenPort.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      wg_clash:
        port: 51820
        proto: udp
        wan:
          via: Home
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::PortCollision { .. }
        )));
    }

    // ── wan ────────────────────────────────────────────────────────────────

    #[test]
    fn wan_invalid_via_node() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: NoSuchNode
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::InvalidWanVia { node_name, .. } if node_name == "NoSuchNode")
        ));
    }

    #[test]
    fn wan_via_node_without_wan_zone() {
        // Home has no wanZone, but a service uses it in wan.via.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaNodeNoWanZone { node_name, .. } if node_name == "Home")
        ));
    }

    #[test]
    fn wan_via_qualified_on_non_client_service() {
        // Qualified form (Node.Network) is invalid on a node-hosted service.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.lan
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::WanViaQualifiedOnNonClient { .. }
        )));
    }

    #[test]
    fn wan_via_network_missing_on_node() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.lan
",
        );
        // Home has no zone "lan" in this fixture, so WanViaNetworkMissing fires.
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaNetworkMissing { network, .. } if network == "lan")
        ));
    }

    #[test]
    fn wan_via_client_not_on_network() {
        // Phone has an IP on "lan" but the service requests "iot" (qualified form).
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
      iot:
        address: 192.168.3.1/24
clients:
  Phone:
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.iot
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaClientNotOnNetwork { network, .. } if network == "iot")
        ));
    }

    #[test]
    fn wan_via_unreachable_client() {
        // Phone has no meshIp and no IPs on Cabin; forwarding via Cabin is impossible.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Cabin
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaUnreachable { node, .. } if node == "Cabin")
        ));
    }

    #[test]
    fn wan_zone_collides_with_zone_name() {
        // wanZone "lan" collides with the zone named "lan" on the same node.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: lan
    zones:
      lan:
        address: 192.168.1.1/24
",
        );
        // `at` points at the wanZone declaration; `with` at the conflicting zone.
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::WanZoneNameCollision { wan_zone, with, at }
                if wan_zone == "lan"
                    && with.to_string() == "nodes.Home.zones.lan"
                    && at.to_string() == "nodes.Home.wanZone"
        )));
    }

    #[test]
    fn wan_zone_reserved_mesh_name() {
        // wanZone "mesh" collides with the splot-managed mesh interface name — a
        // reserved-name error (no config location to point `with` at), distinct
        // from a collision with the operator's own zone.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: mesh
",
        );
        assert!(error_at(
            &r,
            "nodes.Home.wanZone",
            |e| matches!(e, ValidationError::WanZoneReservedName { wan_zone, .. } if wan_zone == "mesh")
        ));
        // ...and it must NOT be misreported as an ordinary name collision.
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::WanZoneNameCollision { .. }
        )));
    }

    #[test]
    fn wan_unused_wan_zone_warning() {
        // wanZone is declared but no service references this node in wan.via.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
",
        );
        assert!(warning_at(&r, "nodes.Home.wanZone", |w| matches!(
            w,
            ValidationWarning::UnusedWanZone { .. }
        )));
    }

    // ── hubs ───────────────────────────────────────────────────────────────

    // Home, in a mesh space with room for hubs. Tests append to it: a hub, other
    // nodes, clients.
    const HUB_HOME: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1";

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

    #[test]
    fn hub_reference_needs_a_hub() {
        let r = report(&format!(
            "{HUB_HOME}
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.1.10
    services:
      ssh: {{ port: 22, proto: tcp, allowFrom: Home.hub }}
"
        ));
        assert!(error_at(
            &r,
            "clients.Phone.services.ssh.allowFrom",
            |e| matches!(e, ValidationError::UnknownRef { reference, .. } if reference.to_string() == "Home.hub")
        ));
    }

    #[test]
    fn hub_network_must_lie_inside_the_mesh_network() {
        for network in ["10.200.49.0/24", "10.0.0.0/8", "10.100.0.0/15"] {
            // The last two hold the mesh network rather than lie inside it.
            let r = report(&format!(
                "{HUB_HOME}
    hub:
      network: {network}
"
            ));
            assert!(
                error_at(&r, "nodes.Home.hub.network", |e| matches!(
                    e,
                    ValidationError::HubOutsideMeshNetwork { .. }
                )),
                "{network}"
            );
        }

        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
"
        ));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::HubOutsideMeshNetwork { .. }
        )));
    }

    fn two_hubs(alpha_hub: &str, zeta_hub: &str) -> ValidationReport {
        report(&format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Alpha:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    hub:
      network: {alpha_hub}
  Zeta:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    hub:
      network: {zeta_hub}
"
        ))
    }

    #[test]
    fn hub_networks_must_not_overlap() {
        // Both ways round: the bigger network on the node checked first, then
        // on the one checked second.
        for (alpha, zeta) in [
            ("10.100.48.0/22", "10.100.49.0/24"),
            ("10.100.49.0/24", "10.100.48.0/22"),
        ] {
            let r = two_hubs(alpha, zeta);
            assert!(
                error_at(&r, "nodes.Zeta.hub.network", |e| matches!(
                    e,
                    ValidationError::NetworkCollision { .. }
                )),
                "{alpha} vs {zeta}"
            );
        }
    }

    #[test]
    fn separate_hub_networks_are_fine() {
        let r = two_hubs("10.100.49.0/24", "10.100.84.0/24");
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::NetworkCollision { .. }
        )));
    }

    fn mesh_ip_in_hub(r: &ValidationReport, path: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::MeshIpInHubNetwork { hub, .. } if hub.to_string() == "nodes.Home.hub.network"),
        )
    }

    #[test]
    fn mesh_ips_must_not_lie_inside_a_hub_network() {
        // One address, one path: a hub network is routed to its node as a whole.
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
  Cabin:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.49.2
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.49.100
"
        ));
        assert!(mesh_ip_in_hub(&r, "nodes.Cabin.meshIp"));
        assert!(mesh_ip_in_hub(&r, "clients.Phone.meshIp"));
        assert!(!mesh_ip_in_hub(&r, "nodes.Home.meshIp"));
    }

    #[test]
    fn own_mesh_ip_must_not_lie_inside_own_hub_network() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.0.0/24
"
        ));
        assert!(mesh_ip_in_hub(&r, "nodes.Home.meshIp"));
    }

    #[test]
    fn hub_client_ip_must_lie_inside_its_hub_network() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.50.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.ip",
            |e| matches!(e, ValidationError::IpOutsideSubnet { .. })
        ));
    }

    #[test]
    fn hub_client_ips_are_unique() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        a-cam:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
        b-cam:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: 10.100.49.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.b-cam.ip",
            |e| matches!(e, ValidationError::IpCollision { with, .. } if with.to_string() == "nodes.Home.hub.clients.a-cam.ip")
        ));
    }

    #[test]
    fn hub_client_names_share_the_node_namespace() {
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      lan:
        address: 192.168.1.1/24
    hub:
      network: 10.100.49.0/24
      clients:
        lan:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
        Phone:
          publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
          ip: 10.100.49.11
clients:
  Phone:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.1.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.lan",
            |e| matches!(e, ValidationError::LocalNameCollision { name, .. } if name == "lan")
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.Phone",
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Phone")
        ));
    }

    fn reserved_name_at(r: &ValidationReport, path: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::ReservedName { name, .. } if name == "hub"),
        )
    }

    #[test]
    fn hub_is_a_reserved_local_name() {
        // Reserved on every node, with or without a hub: `{Node}.hub` refers to
        // the node's hub network.
        let r = report(&format!(
            "{HUB_HOME}
    zones:
      hub:
        address: 192.168.1.1/24
      lan:
        address: 192.168.2.1/24
        devices:
          hub:
            ip: 192.168.2.10
            macs: AA:BB:CC:DD:EE:01
"
        ));
        assert!(reserved_name_at(&r, "nodes.Home.zones.hub"));
        assert!(reserved_name_at(&r, "nodes.Home.zones.lan.devices.hub"));

        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        hub:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
"
        ));
        assert!(reserved_name_at(&r, "nodes.Home.hub.clients.hub"));
    }

    #[test]
    fn hub_tags_must_not_collide_with_global_names() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      tags: Phone
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          tags: Phone
clients:
  Phone:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    meshIp: 10.100.1.10
"
        ));
        for path in ["nodes.Home.hub.tags", "nodes.Home.hub.clients.camera.tags"] {
            assert!(
                error_at(&r, path, |e| matches!(
                    e,
                    ValidationError::TagWithNameCollision { .. }
                )),
                "{path}"
            );
        }
    }

    #[test]
    fn hub_client_needs_its_own_public_key() {
        // The hub client sits between the nodes and the global clients.
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          ip: 10.100.49.10
        doorbell:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.11
clients:
  Phone:
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    meshIp: 10.100.1.10
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.publicKey",
            |e| matches!(e, ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Home.publicKey")
        ));
        assert!(error_at(
            &r,
            "clients.Phone.publicKey",
            |e| matches!(e, ValidationError::DuplicatePublicKey { with, .. } if with.to_string() == "nodes.Home.hub.clients.doorbell.publicKey")
        ));
    }

    #[test]
    fn hub_client_service_ports_must_not_collide() {
        let r = report(&format!(
            "{HUB_HOME}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            http: {{ port: 80, proto: tcp, allowFrom: Home }}
            web: {{ port: 80, proto: tcp, allowFrom: Home }}
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.services.web.port",
            |e| matches!(e, ValidationError::PortCollision { .. })
        ));
    }

    #[test]
    fn hub_client_service_wan_via_must_be_bare() {
        // The qualified form picks one of a global client's networks; a hub client
        // has one address.
        let r = report(&format!(
            "{HUB_HOME}
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            http: {{ port: 80, proto: tcp, wan: {{ via: Home.lan }} }}
"
        ));
        assert!(error_at(
            &r,
            "nodes.Home.hub.clients.camera.services.http.wan.via",
            |e| matches!(e, ValidationError::WanViaQualifiedOnNonClient { .. })
        ));
    }
}
