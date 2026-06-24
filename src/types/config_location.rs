use std::fmt::Display;

use crate::types::identifier::Identifier;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigLocation {
    MeshNetwork,
    Node(Identifier, NodeLoc),
    Client(Identifier, ClientLoc),
}

impl Display for ConfigLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MeshNetwork => write!(f, "meshNetwork"),
            Self::Node(node_id, node_loc) => write!(f, "nodes.{node_id}{node_loc}"),
            Self::Client(client_id, client_loc) => write!(f, "clients.{client_id}{client_loc}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeLoc {
    Root,
    PublicKey,
    Endpoint,
    ListenPort,
    MeshIp,
    Tags,
    WanZone,
    Zone(Identifier, ZoneLoc),
    VpnInterface(Identifier, VpnLoc),
    Service(Identifier, ServiceLoc),
}

impl Display for NodeLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::PublicKey => write!(f, ".publicKey"),
            Self::Endpoint => write!(f, ".endpoint"),
            Self::ListenPort => write!(f, ".listenPort"),
            Self::MeshIp => write!(f, ".meshIp"),
            Self::Tags => write!(f, ".tags"),
            Self::WanZone => write!(f, ".wanZone"),
            Self::Zone(zone_id, zone_loc) => write!(f, ".zones.{zone_id}{zone_loc}"),
            Self::VpnInterface(vpn_int_id, vpn_int_loc) => {
                write!(f, ".vpnInterfaces.{vpn_int_id}{vpn_int_loc}")
            }
            Self::Service(service_id, service_loc) => {
                write!(f, ".services.{service_id}{service_loc}")
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceLoc {
    Root,
    Port,
    Proto,
    AllowFrom,
    Wan(WanLoc),
}

impl Display for ServiceLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Port => write!(f, ".port"),
            Self::Proto => write!(f, ".proto"),
            Self::AllowFrom => write!(f, ".allowFrom"),
            Self::Wan(wan_loc) => write!(f, ".wan{wan_loc}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WanLoc {
    Root,
    Via,
    Sources,
}

impl Display for WanLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Via => write!(f, ".via"),
            Self::Sources => write!(f, ".sources"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZoneLoc {
    Root,
    Address,
    Tags,
    Device(Identifier, DeviceLoc),
}

impl Display for ZoneLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Address => write!(f, ".address"),
            Self::Tags => write!(f, ".tags"),
            Self::Device(device_id, device_loc) => write!(f, ".devices.{device_id}{device_loc}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceLoc {
    Root,
    Ip,
    Macs,
    Tags,
    Service(Identifier, ServiceLoc),
}

impl Display for DeviceLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Ip => write!(f, ".ip"),
            Self::Macs => write!(f, ".macs"),
            Self::Tags => write!(f, ".tags"),
            Self::Service(service_id, service_loc) => {
                write!(f, ".services.{service_id}{service_loc}")
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VpnLoc {
    Root,
    ListenPort,
    Address,
    Tags,
    Client(Identifier, VpnClientLoc),
}

impl Display for VpnLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::ListenPort => write!(f, ".listenPort"),
            Self::Address => write!(f, ".address"),
            Self::Tags => write!(f, ".tags"),
            Self::Client(client_id, client_loc) => write!(f, ".clients.{client_id}{client_loc}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VpnClientLoc {
    Root,
    PublicKey,
    Ip,
    Tags,
    Service(Identifier, ServiceLoc),
}

impl Display for VpnClientLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::PublicKey => write!(f, ".publicKey"),
            Self::Ip => write!(f, ".ip"),
            Self::Tags => write!(f, ".tags"),
            Self::Service(service_id, service_loc) => {
                write!(f, ".services.{service_id}{service_loc}")
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientLoc {
    Root,
    MeshIp,
    PublicKey,
    Macs,
    Tags,
    Ip(Identifier, ClientIpLoc),
    Service(Identifier, ServiceLoc),
}

impl Display for ClientLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::MeshIp => write!(f, ".meshIp"),
            Self::PublicKey => write!(f, ".publicKey"),
            Self::Macs => write!(f, ".macs"),
            Self::Tags => write!(f, ".tags"),
            Self::Ip(node, client_ip_loc) => write!(f, ".ips.{node}{client_ip_loc}"),
            Self::Service(name, service_loc) => write!(f, ".services.{name}{service_loc}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientIpLoc {
    Root,
    Network(Identifier),
}

impl Display for ClientIpLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Network(network_name) => write!(f, ".{network_name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        s.parse().expect("test identifier should be valid")
    }

    #[test]
    fn top_level_paths() {
        assert_eq!(ConfigLocation::MeshNetwork.to_string(), "meshNetwork");
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::Root).to_string(),
            "nodes.Home"
        );
        assert_eq!(
            ConfigLocation::Client(id("Phone"), ClientLoc::Root).to_string(),
            "clients.Phone"
        );
    }

    #[test]
    fn node_scalar_paths() {
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::MeshIp).to_string(),
            "nodes.Home.meshIp"
        );
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::ListenPort).to_string(),
            "nodes.Home.listenPort"
        );
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::WanZone).to_string(),
            "nodes.Home.wanZone"
        );
    }

    #[test]
    fn zone_and_device_paths() {
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::Zone(id("lan"), ZoneLoc::Address))
                .to_string(),
            "nodes.Home.zones.lan.address"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Zone(id("lan"), ZoneLoc::Device(id("printer"), DeviceLoc::Ip))
            )
            .to_string(),
            "nodes.Home.zones.lan.devices.printer.ip"
        );
    }

    #[test]
    fn vpn_interface_client_service_path() {
        // The deepest path in the tree — the shape most prone to a copy-paste slip
        // when hand-writing the nested variants (cf. the names.rs vpn-client bug).
        let loc = ConfigLocation::Node(
            id("Home"),
            NodeLoc::VpnInterface(
                id("vpn"),
                VpnLoc::Client(
                    id("Phone"),
                    VpnClientLoc::Service(id("ssh"), ServiceLoc::Port),
                ),
            ),
        );
        assert_eq!(
            loc.to_string(),
            "nodes.Home.vpnInterfaces.vpn.clients.Phone.services.ssh.port"
        );
    }

    #[test]
    fn client_ip_and_service_wan_paths() {
        assert_eq!(
            ConfigLocation::Client(
                id("Phone"),
                ClientLoc::Ip(id("Home"), ClientIpLoc::Network(id("lan")))
            )
            .to_string(),
            "clients.Phone.ips.Home.lan"
        );
        assert_eq!(
            ConfigLocation::Client(
                id("Phone"),
                ClientLoc::Service(id("http"), ServiceLoc::Wan(WanLoc::Via))
            )
            .to_string(),
            "clients.Phone.services.http.wan.via"
        );
    }

    #[test]
    fn root_leaf_renders_no_trailing_segment() {
        // A `Root` leaf points at the section itself — it must contribute no
        // trailing dot or segment. This is the contract the validator relies on
        // when reporting a name collision "at" the section it names.
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Zone(id("lan"), ZoneLoc::Device(id("printer"), DeviceLoc::Root))
            )
            .to_string(),
            "nodes.Home.zones.lan.devices.printer"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::VpnInterface(id("vpn"), VpnLoc::Client(id("Phone"), VpnClientLoc::Root))
            )
            .to_string(),
            "nodes.Home.vpnInterfaces.vpn.clients.Phone"
        );
    }
}
