use crate::types::{
    identifier::Identifier,
    platform::{DhcpProgram, DnsProgram, FirewallProgram, WireGuardProgram},
};

pub use splot_core::consts::MESH_INTERFACE_NAME;
pub const SPLOT_NAME_PREFIX: &str = "[SPLOT] ";
/// `{Node}.hub` refers to the node's hub network.
pub const HUB_NAME: &str = "hub";

/// The name `{Node}.hub` uses for a node's hub network, as an identifier.
pub fn hub() -> Identifier {
    HUB_NAME.parse().expect("`hub` is an identifier")
}
/// Local names (zones, devices, hub clients) that splot gives a meaning of its
/// own on every node.
pub const RESERVED_LOCAL_NAMES: [&str; 1] = [HUB_NAME];
pub const CURRENT_NODE_IDENTIFIER: &str = "$node";

// What the config takes when a key is left out.

/// Seconds between keepalives (`keepaliveInterval`): WireGuard's suggestion,
/// which works with a wide variety of NATs and firewalls.
pub const DEFAULT_KEEPALIVE_INTERVAL: u16 = 25;
/// Whether a host's WireGuard pairs use a preshared key (`psk`): every pair
/// does unless one end turns it off.
pub const DEFAULT_PSK: bool = true;

/// Seconds a node waits for splot to reach it again and confirm a change it
/// applied, before it puts back what it had (`apply --confirm-within`).
pub const DEFAULT_CONFIRM_WITHIN: u32 = 120;

// What an `os: openwrt` node runs for a concern its `platform` leaves out: what
// OpenWrt ships. A Linux node has no such defaults: it names every concern's.

pub const OPENWRT_WIREGUARD: WireGuardProgram = WireGuardProgram::Netifd;
pub const OPENWRT_FIREWALL: FirewallProgram = FirewallProgram::Fw4;
pub const OPENWRT_DHCP: DhcpProgram = DhcpProgram::Dnsmasq;
pub const OPENWRT_DNS: DnsProgram = DnsProgram::Dnsmasq;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hub_name_is_an_identifier() {
        assert_eq!(hub().as_ref(), HUB_NAME);
    }
}
