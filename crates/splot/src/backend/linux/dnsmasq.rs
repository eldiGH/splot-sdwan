//! The node's DHCP as a dnsmasq config file of splot's own, which the
//! operator's dnsmasq reads (`conf-file=/etc/splot/dnsmasq.conf` in its
//! config): a `dhcp-host` for each lease, and on a zone whose gateway is
//! another box, the routes through the node (option 121) for requests that
//! come in on the zone's interfaces. dnsmasq sets a tag named after the
//! interface a request comes in on.

use std::fmt::Write;

use splot_core::consts::DNSMASQ_PATH;

use crate::{
    model::platform::Platform,
    plan::dhcp::{DhcpPlan, Lease, ZoneRoutes},
    types::identifier::Identifier,
};

/// `dhcp-host=<MACs>,<IP>,<name>`: the address for whichever of its MACs asks.
fn lease(
    Lease {
        hostname, ip, macs, ..
    }: &Lease,
) -> String {
    let macs: Vec<String> = macs.iter().map(ToString::to_string).collect();

    format!("dhcp-host={},{ip},{hostname}", macs.join(","))
}

/// Option 121 for each of the zone's interfaces: the default route through
/// the gateway, then each network through the node.
fn routes(routes: &ZoneRoutes, platform: &Platform) -> Vec<String> {
    let mut list = format!("0.0.0.0/0,{}", routes.gateway);
    for network in &routes.networks {
        let _ = write!(list, ",{network},{}", routes.via);
    }

    platform
        .interfaces(&routes.zone)
        .into_iter()
        .flatten()
        .map(|interface| {
            format!("dhcp-option=tag:{interface},option:classless-static-route,{list}")
        })
        .collect()
}

/// The file, its parts labelled in the config's notation.
pub(super) fn render(node: &Identifier, dhcp: &DhcpPlan, platform: &Platform) -> String {
    let mut text = format!(
        "# splot's DHCP for node {node}: dnsmasq reads it where its config says\n\
         # conf-file={DNSMASQ_PATH}. Written by splot: don't edit.\n"
    );

    for lease in &dhcp.leases {
        let _ = write!(text, "\n# {}\n{}\n", lease.host, self::lease(lease));
    }
    for zone in &dhcp.routes {
        let _ = writeln!(
            text,
            "\n# routes on {}: the default through its gateway, the rest through {node}",
            zone.zone
        );
        for line in routes(zone, platform) {
            let _ = writeln!(text, "{line}");
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support::checked};

    /// Barn's file: Barn isn't its LAN's gateway, which is on two interfaces,
    /// and routes Home's networks and its own iot zone.
    fn barn() -> String {
        let network = checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan: { address: 192.168.1.1/24 }
    hub:
      network: 10.100.10.0/24
  Barn:
    platform:
      os: linux
      wireguard: wg-quick
      firewall: none
      dhcp: dnsmasq
      dns: none
      interfaces: { lan: [eth0, eth1] }
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    listenPort: 51820
    meshIp: 10.100.0.4
    zones:
      lan:
        address: 192.168.4.2/24
        gateway: 192.168.4.1
        devices:
          nvr: { ip: 192.168.4.10, macs: [aa:bb:cc:00:00:08, aa:bb:cc:00:00:07] }
      iot:
        address: 192.168.40.1/24
",
        );
        let node = network.node(&"Barn".parse().unwrap()).unwrap();
        let plan = plan::plan(&network, node.name()).unwrap();

        render(node.name(), plan.dhcp.as_ref().unwrap(), node.platform())
    }

    #[test]
    fn a_lease_is_a_dhcp_host_for_each_of_its_macs() {
        assert!(
            barn().contains(
                "\n# Barn.nvr\ndhcp-host=aa:bb:cc:00:00:07,aa:bb:cc:00:00:08,192.168.4.10,nvr\n"
            ),
            "{}",
            barn()
        );
    }

    #[test]
    fn a_zone_whose_gateway_is_another_box_gets_the_routes_through_the_node_on_its_interfaces() {
        // The mesh (Home's hub inside it), Home's LAN, and Barn's own iot zone,
        // through Barn's address on the LAN; the default through the gateway.
        let routes = "option:classless-static-route,0.0.0.0/0,192.168.4.1,\
                      10.100.0.0/16,192.168.4.2,192.168.1.0/24,192.168.4.2,192.168.40.0/24,192.168.4.2";
        let text = barn();
        for interface in ["eth0", "eth1"] {
            assert!(
                text.contains(&format!("\ndhcp-option=tag:{interface},{routes}\n")),
                "{text}"
            );
        }
        // Not the iot zone's own interfaces: Barn is its gateway.
        assert_eq!(text.matches("dhcp-option=").count(), 2, "{text}");
    }
}
