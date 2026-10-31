//! Which software runs a node, and which of its concerns splot manages.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{
    identifier::Identifier,
    interface::InterfaceName,
    platform::{DhcpProgram, DnsProgram, FirewallProgram, Os, WireGuardProgram},
    ssh::SshDestination,
};

/// A node's platform, checked: per concern the program splot manages it with,
/// or none when splot leaves it alone. Each program runs on the node's OS.
/// And where splot reaches the node over ssh, if the config says, and the
/// interfaces of its zones: each one's, and its wanZone's, where its firewall
/// is nftables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub(super) os: Os,
    pub(super) wireguard: Option<WireGuardProgram>,
    pub(super) firewall: Option<FirewallProgram>,
    pub(super) dhcp: Option<DhcpProgram>,
    pub(super) dns: Option<DnsProgram>,
    pub(super) ssh: Option<SshDestination>,
    pub(super) interfaces: BTreeMap<Identifier, BTreeSet<InterfaceName>>,
}

impl Platform {
    pub fn os(&self) -> Os {
        self.os
    }

    pub fn wireguard(&self) -> Option<WireGuardProgram> {
        self.wireguard
    }

    pub fn firewall(&self) -> Option<FirewallProgram> {
        self.firewall
    }

    pub fn dhcp(&self) -> Option<DhcpProgram> {
        self.dhcp
    }

    pub fn dns(&self) -> Option<DnsProgram> {
        self.dns
    }

    pub fn ssh(&self) -> Option<&SshDestination> {
        self.ssh.as_ref()
    }

    /// The interfaces `zone`, one of the node's zones or its wanZone, is on;
    /// none where the config doesn't say, which it does for each one where the
    /// firewall is nftables.
    pub fn interfaces(&self, zone: &Identifier) -> Option<&BTreeSet<InterfaceName>> {
        self.interfaces.get(zone)
    }
}
