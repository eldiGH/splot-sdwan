use crate::types::platform::{DhcpProgram, DnsProgram, FirewallProgram, WireGuardProgram};

pub const SPLOT_SECTION_PREFIX: &str = "spl_";
pub const SPLOT_NAME_PREFIX: &str = "[SPLOT] ";
pub const MESH_INTERFACE_NAME: &str = "mesh";
/// `{Node}.hub` refers to the node's hub network.
pub const HUB_NAME: &str = "hub";
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

// What an `os: openwrt` node runs for a concern its `platform` leaves out: what
// OpenWrt ships. A Linux node has no such defaults: it names every concern's.

pub const OPENWRT_WIREGUARD: WireGuardProgram = WireGuardProgram::Netifd;
pub const OPENWRT_FIREWALL: FirewallProgram = FirewallProgram::Fw4;
pub const OPENWRT_DHCP: DhcpProgram = DhcpProgram::Dnsmasq;
pub const OPENWRT_DNS: DnsProgram = DnsProgram::Dnsmasq;
