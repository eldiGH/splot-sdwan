//! DHCP: what splot hands out on the nodes whose DHCP it manages.

use std::collections::BTreeMap;

use crate::{
    config::Config,
    model::{
        platform::Platform,
        validator::types::{ValidationError, ValidationReport, ValidationWarning},
    },
    types::{
        config_location::{ClientLoc, ConfigLocation, DeviceLoc, NodeLoc, ZoneLoc},
        dns::DnsLabel,
        identifier::Identifier,
    },
};

/// Where splot manages a node's DHCP, it reserves every address the node's
/// zones give a host, by the host's MACs, and hands the host its name: so each
/// such host needs MACs, and a name that's a host name. Where no DHCP of
/// splot's leases a host an address, its MACs are unused.
pub(super) fn check_dhcp(
    config: &Config,
    platforms: &BTreeMap<Identifier, Platform>,
    report: &mut ValidationReport,
) {
    let managed = |node: &Identifier| platforms.get(node).is_some_and(|p| p.dhcp().is_some());

    for (node_name, node) in &config.nodes {
        for (zone_name, zone) in &node.zones {
            for (device_name, device) in &zone.devices {
                let at = |loc| {
                    ConfigLocation::Node(
                        node_name.clone(),
                        NodeLoc::Zone(zone_name.clone(), ZoneLoc::Device(device_name.clone(), loc)),
                    )
                };
                check_host(
                    device_name,
                    managed(node_name).then_some(node_name),
                    !device.macs.is_empty(),
                    at(DeviceLoc::Root),
                    at(DeviceLoc::Macs),
                    report,
                );
            }
        }
    }

    for (client_name, client) in &config.clients {
        let at = |loc| ConfigLocation::Client(client_name.clone(), loc);
        // The first node that leases it an address speaks for the others.
        check_host(
            client_name,
            client.ips.keys().find(|node| managed(node)),
            !client.macs.is_empty(),
            at(ClientLoc::Root),
            at(ClientLoc::Macs),
            report,
        );
    }
}

/// A host splot's DHCP on `leased_on` leases an address to, or none does.
fn check_host(
    name: &Identifier,
    leased_on: Option<&Identifier>,
    has_macs: bool,
    at: ConfigLocation,
    macs_at: ConfigLocation,
    report: &mut ValidationReport,
) {
    match (leased_on, has_macs) {
        (Some(node), false) => report.errors.push(ValidationError::MacMissing {
            node: node.clone(),
            at: macs_at,
        }),
        (Some(node), true) => {
            if let Err(reason) = name.as_ref().parse::<DnsLabel>() {
                report.errors.push(ValidationError::InvalidHostname {
                    name: name.clone(),
                    node: node.clone(),
                    reason,
                    at,
                });
            }
        }
        (None, true) => report
            .warnings
            .push(ValidationWarning::UnusedMac { at: macs_at }),
        (None, false) => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::validator::types::{ValidationError, ValidationReport, ValidationWarning},
        test_support::{error_at, has_error, has_warning, report},
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

    fn invalid(r: &ValidationReport, path: &str) -> bool {
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

    /// Home and Cabin, each with its DHCP managed or left alone, a device on
    /// each, and Phone on both: `printer` and `nas` have `macs` unless left
    /// out, as Phone has.
    fn two_nodes(home: &str, cabin: &str, printer: &str, nas: &str, phone: &str) -> String {
        format!(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform: {{ os: openwrt, dhcp: {home} }}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer: {{ ip: 192.168.1.50 {printer} }}
  Cabin:
    platform: {{ os: openwrt, dhcp: {cabin} }}
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas: {{ ip: 192.168.2.50 {nas} }}
clients:
  Phone:
    {phone}
    ips:
      Home: {{ lan: 192.168.1.60 }}
      Cabin: {{ lan: 192.168.2.60 }}
"
        )
    }

    const MACS: &str = ", macs: AA:BB:CC:DD:EE:01";
    const OTHER_MACS: &str = ", macs: AA:BB:CC:DD:EE:02";
    const PHONE_MACS: &str = "macs: AA:BB:CC:DD:EE:03";

    fn mac_missing(r: &ValidationReport, path: &str, on: &str) -> bool {
        error_at(
            r,
            path,
            |e| matches!(e, ValidationError::MacMissing { node, .. } if node.as_ref() == on),
        )
    }

    fn unused(r: &ValidationReport, path: &str) -> bool {
        r.warnings.iter().any(|w| {
            matches!(w, ValidationWarning::UnusedMac { .. }) && w.path().to_string() == path
        })
    }

    #[test]
    fn macs_are_optional_where_splot_leaves_dhcp_alone() {
        let r = report(&two_nodes("none", "none", "", "", ""));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(!has_warning(&r, |w| matches!(
            w,
            ValidationWarning::UnusedMac { .. }
        )));
    }

    #[test]
    fn a_host_splots_dhcp_leases_an_address_to_needs_macs() {
        let r = report(&two_nodes("dnsmasq", "none", "", "", ""));
        assert!(mac_missing(
            &r,
            "nodes.Home.zones.lan.devices.printer.macs",
            "Home"
        ));
        assert!(mac_missing(&r, "clients.Phone.macs", "Home"));
        // Cabin leases nothing.
        assert!(!has_error(&r, |e| e.path().to_string().contains("nas")));

        // Either node speaks for the client, whichever sorts first.
        let r = report(&two_nodes("none", "dnsmasq", "", "", ""));
        assert!(mac_missing(
            &r,
            "nodes.Cabin.zones.lan.devices.nas.macs",
            "Cabin"
        ));
        assert!(mac_missing(&r, "clients.Phone.macs", "Cabin"));
        assert!(!has_error(&r, |e| e.path().to_string().contains("printer")));

        let r = report(&two_nodes(
            "dnsmasq", "dnsmasq", MACS, OTHER_MACS, PHONE_MACS,
        ));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }

    #[test]
    fn macs_no_dhcp_of_splots_leases_by_are_unused() {
        let r = report(&two_nodes("none", "dnsmasq", MACS, OTHER_MACS, PHONE_MACS));
        assert!(unused(&r, "nodes.Home.zones.lan.devices.printer.macs"));
        assert!(!unused(&r, "nodes.Cabin.zones.lan.devices.nas.macs"));
        // Cabin leases Phone an address.
        assert!(!unused(&r, "clients.Phone.macs"));

        let r = report(&two_nodes("none", "none", MACS, OTHER_MACS, PHONE_MACS));
        assert!(unused(&r, "nodes.Cabin.zones.lan.devices.nas.macs"));
        assert!(unused(&r, "clients.Phone.macs"));
    }

    #[test]
    fn a_client_on_no_zone_uses_no_macs() {
        let r = report(&format!(
            "{}  Laptop:\n    macs: AA:BB:CC:DD:EE:04\n",
            two_nodes("dnsmasq", "dnsmasq", MACS, OTHER_MACS, PHONE_MACS)
        ));
        assert!(unused(&r, "clients.Laptop.macs"));
        assert!(!unused(&r, "clients.Phone.macs"));
    }
}
