//! The node's DHCP: static leases on its zones.

use std::{collections::BTreeSet, fmt, net::Ipv4Addr};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
    },
    types::{identifier::Identifier, mac::MacAddress},
};

#[derive(Debug)]
pub struct DhcpPlan {
    pub leases: Vec<Lease>,
}

/// A static lease: the host's IP on one of this node's zones, for its MACs.
#[derive(Debug)]
pub struct Lease {
    pub host: HostRef,
    pub ip: Ipv4Addr,
    pub macs: BTreeSet<MacAddress>,
}

/// A lease for each address a host with MACs has on this node's zones: the
/// node's devices, and global clients on its zones.
pub(super) fn plan(network: &Network, own_name: &Identifier) -> DhcpPlan {
    let leases = network
        .hosts()
        .iter()
        .filter(|host| !host.macs().is_empty())
        .flat_map(|host| {
            host.addresses()
                .iter()
                .filter(|address| {
                    matches!(address.place(), Place::Zone { node, .. } if node == own_name)
                })
                .map(|address| Lease {
                    host: host.id().clone(),
                    ip: address.ip(),
                    macs: host.macs().clone(),
                })
        })
        .collect();

    DhcpPlan { leases }
}

impl fmt::Display for DhcpPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for Lease { host, ip, macs } in &self.leases {
            writeln!(f, "lease {host}: {ip} for {}", super::list(macs))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    const FIXTURE: &str = "
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
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
          macless:
            ip: 192.168.1.51
            macs: []
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:01
clients:
  Phone:
    macs: BB:CC:DD:EE:FF:00
    ips:
      Home:
        lan: 192.168.1.60
      Cabin:
        lan: 192.168.2.60
  MeshOnly:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.0.100
";

    /// Home's leases, one line each.
    fn leases() -> Vec<String> {
        let plan = plan(&checked(FIXTURE), &"Home".parse().unwrap());
        plan.to_string().lines().map(str::to_owned).collect()
    }

    #[test]
    fn devices_and_global_clients_with_macs_get_leases_on_this_nodes_zones() {
        assert_eq!(
            leases(),
            [
                "lease Home.printer: 192.168.1.50 for [aa:bb:cc:dd:ee:ff]",
                "lease Phone: 192.168.1.60 for [bb:cc:dd:ee:ff:00]",
            ]
        );
        // Not: macless (no MACs), Cabin.nas and Phone's Cabin IP (Cabin's to
        // lease), MeshOnly (no zone IP).
    }
}
