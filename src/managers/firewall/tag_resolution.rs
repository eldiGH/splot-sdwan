use std::iter;

use crate::{
    config::{Client, Config, Node},
    managers::firewall::types::TagMap,
    types::{
        allow_from_ref::AllowFromRef, identifier::Identifier, ip::Ipv4Network, zone_ref::ZoneRef,
    },
};

fn add_tags(
    tags_map: &mut TagMap,
    network: Ipv4Network,
    tags: impl IntoIterator<Item = AllowFromRef>,
    zone_name: &ZoneRef,
) {
    for tag in tags {
        tags_map
            .entry(tag)
            .or_default()
            .entry(zone_name.clone())
            .or_default()
            .insert(network);
    }
}

fn add_current_node_identifier_tag(node: &Node, tags_map: &mut TagMap) {
    for (zone_name, zone) in &node.zones {
        add_tags(
            tags_map,
            Ipv4Network::host(zone.address.ip()),
            [AllowFromRef::SelfNode],
            &ZoneRef::Named(zone_name.clone()),
        );
    }
}

fn add_node_tag(node_name: &Identifier, node: &Node, tags_map: &mut TagMap) {
    let node_tags = iter::once(node_name.to_owned())
        .chain(node.tags.iter().cloned())
        .map(AllowFromRef::Bare);

    for (zone_name, zone) in &node.zones {
        add_tags(
            tags_map,
            zone.address.network(),
            node_tags.clone(),
            &ZoneRef::Named(zone_name.clone()),
        );
    }

    if let Some(hub) = &node.hub {
        add_tags(tags_map, hub.network, node_tags, &ZoneRef::Mesh);
    }
}

fn add_client_tag(
    client_name: &Identifier,
    client: &Client,
    own_name: &Identifier,
    tags_map: &mut TagMap,
) {
    let tags: Vec<AllowFromRef> = iter::once(client_name.clone())
        .chain(client.tags.iter().cloned())
        .map(AllowFromRef::Bare)
        .collect();

    if let Some(mesh_ip) = client.mesh_ip {
        add_tags(
            tags_map,
            Ipv4Network::host(mesh_ip),
            tags.iter().cloned(),
            &ZoneRef::Mesh,
        );
    }

    for (node_name, networks) in &client.ips {
        for (local_name, ip) in networks {
            let zone_ref = if node_name == own_name {
                ZoneRef::Named(local_name.clone())
            } else {
                ZoneRef::Mesh
            };

            add_tags(
                tags_map,
                Ipv4Network::host(*ip),
                tags.iter().cloned(),
                &zone_ref,
            );
        }
    }
}

fn add_zones_tags(node_name: &Identifier, node: &Node, tags_map: &mut TagMap) {
    for (zone_name, zone) in &node.zones {
        let zone_ref = ZoneRef::Named(zone_name.clone());
        let zone_tags = iter::once(AllowFromRef::nested(node_name.clone(), zone_name.clone()))
            .chain(zone.tags.iter().cloned().map(AllowFromRef::Bare));

        add_tags(tags_map, zone.address.network(), zone_tags, &zone_ref);

        for (device_name, device) in &zone.devices {
            let device_tags =
                iter::once(AllowFromRef::nested(node_name.clone(), device_name.clone()))
                    .chain(device.tags.iter().cloned().map(AllowFromRef::Bare));
            add_tags(
                tags_map,
                Ipv4Network::host(device.ip),
                device_tags,
                &zone_ref,
            );
        }
    }
}

/// Everything on a hub comes in over the mesh interface: it resolves under the
/// mesh zone, on the hub's own node as on every other.
fn add_hub_tags(node_name: &Identifier, node: &Node, tags_map: &mut TagMap) {
    let Some(hub) = &node.hub else { return };

    let hub_tags = iter::once(AllowFromRef::nested(node_name.clone(), Identifier::hub()))
        .chain(hub.tags.iter().cloned().map(AllowFromRef::Bare));
    add_tags(tags_map, hub.network, hub_tags, &ZoneRef::Mesh);

    for (client_name, client) in &hub.clients {
        let client_tags = iter::once(AllowFromRef::nested(node_name.clone(), client_name.clone()))
            .chain(client.tags.iter().cloned().map(AllowFromRef::Bare));
        add_tags(
            tags_map,
            Ipv4Network::host(client.ip),
            client_tags,
            &ZoneRef::Mesh,
        );
    }
}

pub fn build_tags_resolution_map(config: &Config, own_name: &Identifier) -> TagMap {
    let mut tags_map: TagMap = TagMap::new();

    for (node_name, node) in &config.nodes {
        if node_name == own_name {
            add_current_node_identifier_tag(node, &mut tags_map);
        }

        add_node_tag(node_name, node, &mut tags_map);

        add_zones_tags(node_name, node, &mut tags_map);
        add_hub_tags(node_name, node, &mut tags_map);
    }

    for (client_name, client) in &config.clients {
        add_client_tag(client_name, client, own_name, &mut tags_map);
    }

    tags_map
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::test_support::config;

    // Home: zone lan (192.168.1.1/24) with device printer (192.168.1.50, tag printable)
    //       zone guest (192.168.2.1/24)
    //       hub 10.100.49.0/24 (tag cameras) with client doorcam (10.100.49.10, tag outdoor)
    //       node tags: server
    // Cabin: zone lan (192.168.3.1/24)
    // Phone: meshIp 10.100.0.100, ips.Home.lan 192.168.1.60, ips.Cabin.lan 192.168.3.10, tag mobile
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    tags: server
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
            tags: printable
      guest:
        address: 192.168.2.1/24
    hub:
      network: 10.100.49.0/24
      tags: cameras
      clients:
        doorcam:
          publicKey: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA=
          ip: 10.100.49.10
          tags: outdoor
  Cabin:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.3.1/24
clients:
  Phone:
    publicKey: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
    meshIp: 10.100.0.100
    tags: mobile
    ips:
      Home:
        lan: 192.168.1.60
      Cabin:
        lan: 192.168.3.10
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn net(s: &str) -> Ipv4Network {
        s.parse().unwrap()
    }

    fn bare(s: &str) -> AllowFromRef {
        AllowFromRef::Bare(id(s))
    }

    fn nested(node: &str, local: &str) -> AllowFromRef {
        AllowFromRef::nested(id(node), id(local))
    }

    fn map_for(own: &str) -> TagMap {
        let cfg = config(FIXTURE);
        build_tags_resolution_map(&cfg, &id(own))
    }

    fn get(map: &TagMap, key: &AllowFromRef, zone: &ZoneRef) -> BTreeSet<Ipv4Network> {
        map.get(key)
            .and_then(|r| r.get(zone))
            .cloned()
            .unwrap_or_default()
    }

    // ── node bare tag → subnets ────────────────────────────────────────────

    #[test]
    fn node_bare_tag_yields_zone_subnets() {
        let m = map_for("Home");
        assert!(
            get(&m, &bare("Home"), &ZoneRef::Named(id("lan"))).contains(&net("192.168.1.0/24"))
        );
        assert!(
            get(&m, &bare("Home"), &ZoneRef::Named(id("guest"))).contains(&net("192.168.2.0/24"))
        );
    }

    #[test]
    fn node_bare_tag_is_subnet_not_host() {
        let m = map_for("Home");
        let lan = get(&m, &bare("Home"), &ZoneRef::Named(id("lan")));
        assert!(lan.contains(&net("192.168.1.0/24")));
        assert!(!lan.contains(&net("192.168.1.1/32")));
    }

    // ── $node → host IPs, scoped to own node ──────────────────────────────

    #[test]
    fn self_node_yields_host_ips_for_own_node() {
        let m = map_for("Home");
        let lan = get(&m, &AllowFromRef::SelfNode, &ZoneRef::Named(id("lan")));
        assert!(lan.contains(&net("192.168.1.1/32")));
        assert!(!lan.contains(&net("192.168.1.0/24")));
    }

    #[test]
    fn self_node_covers_all_own_zones() {
        let m = map_for("Home");
        assert!(!get(&m, &AllowFromRef::SelfNode, &ZoneRef::Named(id("lan"))).is_empty());
        assert!(!get(&m, &AllowFromRef::SelfNode, &ZoneRef::Named(id("guest"))).is_empty());
    }

    #[test]
    fn self_node_scoped_to_own_node_only() {
        // When generating for Cabin, $node maps to Cabin's lan address, not Home's.
        let m = map_for("Cabin");
        let lan = get(&m, &AllowFromRef::SelfNode, &ZoneRef::Named(id("lan")));
        assert!(
            lan.contains(&net("192.168.3.1/32")),
            "should contain Cabin lan host"
        );
        assert!(
            !lan.contains(&net("192.168.1.1/32")),
            "must not contain Home lan host"
        );
    }

    // ── nested qualified refs ──────────────────────────────────────────────

    #[test]
    fn nested_zone_yields_zone_subnet() {
        let m = map_for("Home");
        let nets = get(&m, &nested("Home", "lan"), &ZoneRef::Named(id("lan")));
        assert!(nets.contains(&net("192.168.1.0/24")));
    }

    #[test]
    fn nested_device_yields_host_ip() {
        let m = map_for("Home");
        let nets = get(&m, &nested("Home", "printer"), &ZoneRef::Named(id("lan")));
        assert!(nets.contains(&net("192.168.1.50/32")));
        assert!(!nets.contains(&net("192.168.1.0/24")));
    }

    // ── explicit tags ──────────────────────────────────────────────────────

    #[test]
    fn explicit_node_tag_accumulates_same_as_node_name() {
        let m = map_for("Home");
        // "server" is a tag on node Home → same subnets as bare("Home")
        let by_tag = get(&m, &bare("server"), &ZoneRef::Named(id("lan")));
        let by_name = get(&m, &bare("Home"), &ZoneRef::Named(id("lan")));
        assert_eq!(by_tag, by_name);
    }

    #[test]
    fn explicit_device_tag_maps_to_device_host() {
        let m = map_for("Home");
        let nets = get(&m, &bare("printable"), &ZoneRef::Named(id("lan")));
        assert!(nets.contains(&net("192.168.1.50/32")));
    }

    // ── hub: everything on it comes in over the mesh ───────────────────────

    #[test]
    fn nested_hub_yields_hub_network_under_mesh() {
        let m = map_for("Home");
        let nets = get(&m, &nested("Home", "hub"), &ZoneRef::Mesh);
        assert_eq!(nets, BTreeSet::from([net("10.100.49.0/24")]));
    }

    #[test]
    fn hub_tag_yields_hub_network() {
        let m = map_for("Home");
        let nets = get(&m, &bare("cameras"), &ZoneRef::Mesh);
        assert_eq!(nets, BTreeSet::from([net("10.100.49.0/24")]));
    }

    #[test]
    fn node_bare_tag_includes_hub_network() {
        let m = map_for("Home");
        assert!(get(&m, &bare("Home"), &ZoneRef::Mesh).contains(&net("10.100.49.0/24")));
        assert!(get(&m, &bare("server"), &ZoneRef::Mesh).contains(&net("10.100.49.0/24")));
    }

    #[test]
    fn nested_hub_client_yields_host_ip_under_mesh() {
        let m = map_for("Home");
        let nets = get(&m, &nested("Home", "doorcam"), &ZoneRef::Mesh);
        assert_eq!(nets, BTreeSet::from([net("10.100.49.10/32")]));
    }

    #[test]
    fn hub_client_tag_maps_to_client_host() {
        let m = map_for("Home");
        let nets = get(&m, &bare("outdoor"), &ZoneRef::Mesh);
        assert_eq!(nets, BTreeSet::from([net("10.100.49.10/32")]));
    }

    #[test]
    fn hub_resolves_the_same_on_other_nodes() {
        let m = map_for("Cabin");
        assert_eq!(
            get(&m, &nested("Home", "doorcam"), &ZoneRef::Mesh),
            BTreeSet::from([net("10.100.49.10/32")])
        );
        assert_eq!(
            get(&m, &nested("Home", "hub"), &ZoneRef::Mesh),
            BTreeSet::from([net("10.100.49.0/24")])
        );
    }

    // ── client tag resolution ──────────────────────────────────────────────

    #[test]
    fn client_mesh_ip_goes_under_mesh_zone() {
        let m = map_for("Home");
        let nets = get(&m, &bare("Phone"), &ZoneRef::Mesh);
        assert!(nets.contains(&net("10.100.0.100/32")));
    }

    #[test]
    fn client_own_node_zone_ip_goes_under_named_zone() {
        // Phone.ips.Home.lan is on the own node → Named("lan"), not Mesh.
        let m = map_for("Home");
        let named = get(&m, &bare("Phone"), &ZoneRef::Named(id("lan")));
        assert!(named.contains(&net("192.168.1.60/32")));
    }

    #[test]
    fn client_remote_node_zone_ip_goes_under_mesh() {
        // Phone.ips.Cabin.lan is on a remote node → folded into Mesh zone.
        let m = map_for("Home");
        let mesh = get(&m, &bare("Phone"), &ZoneRef::Mesh);
        assert!(mesh.contains(&net("192.168.3.10/32")));
    }

    #[test]
    fn explicit_client_tag_same_resolution_as_client_name() {
        let m = map_for("Home");
        let by_tag = get(&m, &bare("mobile"), &ZoneRef::Mesh);
        let by_name = get(&m, &bare("Phone"), &ZoneRef::Mesh);
        assert_eq!(by_tag, by_name);
    }
}
