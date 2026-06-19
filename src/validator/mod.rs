mod entities;
mod names;
mod networks;
mod ports;
mod references;
mod tags;
pub mod types;
mod wan;

use std::collections::HashSet;

use crate::{
    config::Config,
    types::allow_from_ref::AllowFromRef,
    validator::{
        entities::check_entities, names::validate_names, networks::check_networks,
        ports::check_ports, references::check_references_resolution, tags::validate_tags,
        types::ValidationReport, wan::check_wan,
    },
};

pub fn validate_config(config: &Config) -> ValidationReport {
    let mut report = ValidationReport::default();

    let names = validate_names(config, &mut report);
    let tags = validate_tags(config, &mut report, &names);
    let refs: HashSet<AllowFromRef> = names.into_iter().chain(tags).collect();
    check_references_resolution(config, &refs, &mut report);

    check_entities(config, &mut report);

    check_networks(config, &mut report);

    check_ports(config, &mut report);

    check_wan(config, &mut report);

    report
}

#[cfg(test)]
mod tests {
    use crate::{
        test_support::{has_error, has_warning, report},
        validator::types::{ValidationError, ValidationWarning},
    };

    // A minimal config that passes every validator pass with no diagnostics.
    const CLEAN: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
clients:
  Phone:
    publicKey: BBBB
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

    // ── names ──────────────────────────────────────────────────────────────

    #[test]
    fn names_global_name_collision() {
        // Node and client share the name "Phone".
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Phone:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: BBBB
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
    publicKey: AAAA
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
        assert!(has_error(
            &r,
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
    publicKey: AAAA
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
    publicKey: BBBB
    meshIp: 10.100.0.100
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::LocalShadowsGlobal { name, .. } if name == "Phone")
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
    publicKey: AAAA
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCC
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Phone:
    publicKey: BBBB
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        tags: admin
clients:
  Phone:
    publicKey: BBBB
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
            ValidationError::PublicKeyMissing {
                required_for_mesh: true,
                ..
            }
        )));
    }

    #[test]
    fn entities_unused_public_key_warning() {
        // Client with publicKey but no meshIp and no VPN IPs.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
clients:
  Orphan:
    publicKey: BBBB
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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

    // ── networks ───────────────────────────────────────────────────────────

    #[test]
    fn networks_collision_mesh_and_zone_overlap() {
        // Zone 192.168.1.0/24 overlaps with meshNetwork 192.168.1.0/24.
        let r = report(
            "
meshNetwork: 192.168.1.0/24
nodes:
  Home:
    publicKey: AAAA
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCC
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
    publicKey: AAAA
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
    publicKey: AAAA
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
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::IpOutsideSubnet { .. }
        )));
    }

    #[test]
    fn networks_ip_collision_two_nodes_same_mesh_ip() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    publicKey: CCCC
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
    publicKey: AAAA
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

    // ── ports ──────────────────────────────────────────────────────────────

    #[test]
    fn ports_internal_collision_two_node_services() {
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
clients:
  Phone:
    publicKey: BBBB
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
        // Phone has an IP on "lan" but the service requests "vpn_a" (qualified form).
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
    vpnInterfaces:
      vpn_a:
        listenPort: 51821
        address: 10.8.1.1/24
        clients: {}
clients:
  Phone:
    publicKey: BBBB
    macs: AA:BB:CC:DD:EE:FF
    ips:
      Home:
        lan: 192.168.1.50
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home.vpn_a
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanViaClientNotOnNetwork { network, .. } if network == "vpn_a")
        ));
    }

    #[test]
    fn wan_via_ambiguous_vpn() {
        // Phone has IPs on two VPN interfaces of Home; bare via can't pick one.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    vpnInterfaces:
      vpn_a:
        listenPort: 51821
        address: 10.8.1.1/24
        clients: {}
      vpn_b:
        listenPort: 51822
        address: 10.8.2.1/24
        clients: {}
clients:
  Phone:
    publicKey: BBBB
    ips:
      Home:
        vpn_a: 10.8.1.10
        vpn_b: 10.8.2.10
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
",
        );
        assert!(has_error(&r, |e| matches!(
            e,
            ValidationError::WanViaAmbiguous { .. }
        )));
    }

    #[test]
    fn wan_via_unreachable_client() {
        // Phone has no meshIp and no IPs on Cabin; forwarding via Cabin is impossible.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
  Cabin:
    publicKey: CCCC
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
clients:
  Phone:
    publicKey: BBBB
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
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: lan
    zones:
      lan:
        address: 192.168.1.1/24
",
        );
        assert!(has_error(
            &r,
            |e| matches!(e, ValidationError::WanZoneNameCollision { wan_zone, .. } if wan_zone == "lan")
        ));
    }

    #[test]
    fn wan_unused_wan_zone_warning() {
        // wanZone is declared but no service references this node in wan.via.
        let r = report(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
",
        );
        assert!(has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedWanZone { .. }
        )));
    }
}
