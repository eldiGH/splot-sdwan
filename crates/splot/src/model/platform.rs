//! Which software runs a node, and which of its concerns splot manages.

use crate::types::{
    platform::{DhcpProgram, DnsProgram, FirewallProgram, Os, WireGuardProgram},
    ssh::SshDestination,
};

/// A node's platform, checked: per concern the program splot manages it with,
/// or none when splot leaves it alone. Each program runs on the node's OS.
/// And where splot reaches the node over ssh, if the config says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub(super) os: Os,
    pub(super) wireguard: Option<WireGuardProgram>,
    pub(super) firewall: Option<FirewallProgram>,
    pub(super) dhcp: Option<DhcpProgram>,
    pub(super) dns: Option<DnsProgram>,
    pub(super) ssh: Option<SshDestination>,
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

    pub fn ssh(&self) -> Option<&SshDestination> {
        self.ssh.as_ref()
    }
}
