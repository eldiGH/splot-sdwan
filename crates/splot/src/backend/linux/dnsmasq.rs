//! The node's DHCP and DNS as a dnsmasq config file of splot's own, which the
//! operator's dnsmasq reads (`conf-file=/etc/splot/dnsmasq.conf` in its
//! config). The DHCP: a `dhcp-host` for each lease, and on a zone whose
//! gateway is another box, the routes through the node (option 121) for
//! requests that come in on the zone's interfaces (dnsmasq sets a tag named
//! after the interface a request comes in on). The DNS: the node's own domain
//! answered there alone, its names (`host-record`, an address and its reverse;
//! `cname`, an alias), the other nodes' domains forwarded to them, and the
//! endpoint names inside a mesh domain sent to the usual upstream servers.

use std::fmt::Write;

use splot_core::consts::DNSMASQ_PATH;

use crate::{
    model::platform::Platform,
    plan::{
        dhcp::{DhcpPlan, Lease, ZoneRoutes},
        dns::DnsPlan,
    },
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

/// The DNS's lines.
fn dns(text: &mut String, dns: &DnsPlan) {
    if let Some(domain) = &dns.local {
        let _ = write!(
            text,
            "\n# {domain}, answered here alone\nlocal=/{domain}/\n"
        );
    }
    for record in &dns.records {
        let _ = write!(
            text,
            "\n# {}\nhost-record={},{}\n",
            record.host, record.name, record.ip
        );
    }
    for alias in &dns.aliases {
        let _ = write!(
            text,
            "\n# {} {}\ncname={},{}\n",
            alias.host, alias.service, alias.name, alias.target
        );
    }
    for forward in &dns.forwards {
        let _ = write!(
            text,
            "\n# {}'s domain, forwarded to it\nserver=/{}/{}\nrebind-domain-ok=/{}/\n",
            forward.node, forward.domain, forward.address, forward.domain
        );
    }
    for name in &dns.public {
        let _ = write!(
            text,
            "\n# an endpoint, asked of public DNS: never through the mesh\nserver=/{name}/#\n"
        );
    }
}

/// The file, its parts labelled in the config's notation; none where splot
/// leaves both the DHCP and the DNS alone.
pub(super) fn render(
    node: &Identifier,
    dhcp: Option<&DhcpPlan>,
    dns: Option<&DnsPlan>,
    platform: &Platform,
) -> Option<String> {
    if dhcp.is_none() && dns.is_none() {
        return None;
    }
    let mut text = format!(
        "# splot's DHCP and DNS for node {node}: dnsmasq reads it where its config\n\
         # says conf-file={DNSMASQ_PATH}. Written by splot: don't edit.\n"
    );
    if let Some(dns) = dns {
        self::dns(&mut text, dns);
    }
    let Some(dhcp) = dhcp else {
        return Some(text);
    };

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

    Some(text)
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

        render(
            node.name(),
            plan.dhcp.as_ref(),
            plan.dns.as_ref(),
            node.platform(),
        )
        .unwrap()
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
