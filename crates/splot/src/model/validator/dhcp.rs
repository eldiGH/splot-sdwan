//! DHCP: what splot hands out on the nodes whose DHCP it manages.

use std::collections::BTreeMap;

use crate::{
    config::Config,
    model::{
        platform::Platform,
        validator::types::{ValidationError, ValidationReport},
    },
    types::{
        config_location::{ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, ZoneLoc},
        dns::DnsLabel,
        identifier::Identifier,
    },
};

/// Every host splot leases an address to is handed its name as its host name:
/// a device with MACs on a node whose DHCP splot manages, and a global client
/// with MACs and an address on one. So the name must be one.
pub(super) fn check_dhcp(
    config: &Config,
    platforms: &BTreeMap<Identifier, Platform>,
    report: &mut ValidationReport,
) {
    let managed = |node: &Identifier| platforms.get(node).is_some_and(|p| p.dhcp().is_some());
    let mut check = |name: &Identifier, node: &Identifier, at: ConfigLocation| {
        if let Err(reason) = name.as_ref().parse::<DnsLabel>() {
            report.errors.push(ValidationError::InvalidHostname {
                name: name.clone(),
                node: node.clone(),
                reason,
                at,
            });
        }
    };

    for (node_name, node) in config.nodes.iter().filter(|(name, _)| managed(name)) {
        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                if device.macs.is_empty() {
                    continue;
                }
                let at = ConfigLocation::Node(
                    node_name.clone(),
                    NodeLoc::Zone(
                        zone_name.clone(),
                        ZoneLoc::Device(device_name.clone(), DeviceLoc::Root),
                    ),
                );
                check(device_name, node_name, at);
            }
        }
    }

    for (client_name, client) in &config.clients {
        if client.macs.is_empty() {
            continue;
        }
        // Once, for the first node that leases it an address.
        if let Some(node) = client.ips.keys().find(|node| managed(node)) {
            check(
                client_name,
                node,
                ConfigLocation::Client(client_name.clone(), ClientLoc::Root),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::ValidationError,
        test_support::{error_at, has_error, report},
    };

    /// Home, its DHCP managed or left alone, with `device` on its LAN and
    /// `client` on it with MACs.
    fn fixture(dhcp: &str, device: &str, client: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
      dhcp: {dhcp}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          {device}: {{ ip: 192.168.1.50, macs: AA:BB:CC:DD:EE:FF }}
clients:
  {client}:
    macs: BB:CC:DD:EE:FF:00
    ips:
      Home:
        lan: 192.168.1.60
"
        )
    }

    fn invalid(r: &crate::model::validator::types::ValidationReport, path: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::InvalidHostname { node, .. } if node.as_ref() == "Home"),
        )
    }

    #[test]
    fn a_name_handed_out_by_splots_dhcp_must_be_a_host_name() {
        let r = report(&fixture("dnsmasq", "my_printer", "Phone_2"));
        assert!(invalid(&r, "nodes.Home.zones.lan.devices.my_printer"));
        assert!(invalid(&r, "clients.Phone_2"));

        let r = report(&fixture("dnsmasq", "printer-", "Phone"));
        assert!(invalid(&r, "nodes.Home.zones.lan.devices.printer-"));
        assert!(!invalid(&r, "clients.Phone"));
    }

    #[test]
    fn a_host_without_macs_gets_no_lease_so_its_name_is_no_host_name() {
        let r = report(&fixture("dnsmasq", "printer", "Phone").replace(
            "clients:",
            "          my_scanner: { ip: 192.168.1.51, macs: [] }\nclients:",
        ));
        assert!(!invalid(&r, "nodes.Home.zones.lan.devices.my_scanner"));

        let r = report(
            &fixture("dnsmasq", "printer", "Phone_2").replace("    macs: BB:CC:DD:EE:FF:00\n", ""),
        );
        assert!(!invalid(&r, "clients.Phone_2"));
    }

    #[test]
    fn host_names_pass() {
        let r = report(&fixture("dnsmasq", "Printer-2", "Phone"));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::InvalidHostname { .. }
        )));
    }

    #[test]
    fn a_name_no_dhcp_of_splots_hands_out_may_be_any_name() {
        // DHCP left alone: splot leases nothing on Home.
        let r = report(&fixture("none", "my_printer", "Phone_2"));
        assert!(!has_error(&r, |e| matches!(
            e,
            ValidationError::InvalidHostname { .. }
        )));
    }
}
