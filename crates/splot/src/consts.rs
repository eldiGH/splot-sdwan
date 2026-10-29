use crate::types::platform::{DhcpProgram, DnsProgram, FirewallProgram, WireGuardProgram};

pub use splot_core::consts::MESH_INTERFACE_NAME;
pub const SPLOT_NAME_PREFIX: &str = "[SPLOT] ";
pub const CURRENT_NODE_IDENTIFIER: &str = "$node";
/// `{Node}.$hub` refers to the node's hub network.
pub const HUB_IDENTIFIER: &str = "$hub";

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
