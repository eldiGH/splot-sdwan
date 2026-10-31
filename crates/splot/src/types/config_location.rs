use std::fmt::Display;

use crate::types::{identifier::Identifier, platform::Concern};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigLocation {
    /// The nodes as a whole.
    Nodes,
    Node(Identifier, NodeLoc),
    Client(Identifier, ClientLoc),
}

impl Display for ConfigLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nodes => write!(f, "nodes"),
            Self::Node(node_id, node_loc) => write!(f, "nodes.{node_id}{node_loc}"),
            Self::Client(client_id, client_loc) => write!(f, "clients.{client_id}{client_loc}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeLoc {
    Root,
    Platform(PlatformLoc),
    PublicKey,
    Endpoint,
    ListenPort,
    MeshIp,
    Tags,
    WanZone,
    Zone(Identifier, ZoneLoc),
    Hub(HubLoc),
    Service(Identifier, ServiceLoc),
    Dns(DnsLoc),
}

/// Where in a node's `dns` block.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DnsLoc {
    Domain,
    Address,
}

impl Display for DnsLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain => write!(f, ".domain"),
            Self::Address => write!(f, ".address"),
        }
    }
}

impl Display for NodeLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Platform(platform_loc) => write!(f, ".platform{platform_loc}"),
            Self::PublicKey => write!(f, ".publicKey"),
            Self::Endpoint => write!(f, ".endpoint"),
            Self::ListenPort => write!(f, ".listenPort"),
            Self::MeshIp => write!(f, ".meshIp"),
            Self::Tags => write!(f, ".tags"),
            Self::WanZone => write!(f, ".wanZone"),
            Self::Zone(zone_id, zone_loc) => write!(f, ".zones.{zone_id}{zone_loc}"),
            Self::Hub(hub_loc) => write!(f, ".hub{hub_loc}"),
            Self::Service(service_id, service_loc) => {
                write!(f, ".services.{service_id}{service_loc}")
            }
            Self::Dns(dns_loc) => write!(f, ".dns{dns_loc}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlatformLoc {
    Root,
    Concern(Concern),
    Interfaces,
    Interface(Identifier),
}

impl Display for PlatformLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Concern(concern) => write!(f, ".{concern}"),
            Self::Interfaces => write!(f, ".interfaces"),
            Self::Interface(zone) => write!(f, ".interfaces.{zone}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceLoc {
    Root,
    Port,
    AllowFrom,
    Wan(WanLoc),
    Dns,
}

impl Display for ServiceLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Port => write!(f, ".port"),
            Self::AllowFrom => write!(f, ".allowFrom"),
            Self::Wan(wan_loc) => write!(f, ".wan{wan_loc}"),
            Self::Dns => write!(f, ".dns"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WanLoc {
    Via,
}

impl Display for WanLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Via => write!(f, ".via"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZoneLoc {
    Root,
    Address,
    Gateway,
    Tags,
    Device(Identifier, DeviceLoc),
}

impl Display for ZoneLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Address => write!(f, ".address"),
            Self::Gateway => write!(f, ".gateway"),
            Self::Tags => write!(f, ".tags"),
            Self::Device(device_id, device_loc) => write!(f, ".devices.{device_id}{device_loc}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HubLoc {
    Root,
    Network,
    Tags,
    Client(Identifier, HubClientLoc),
}

impl Display for HubLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, ""),
            Self::Network => write!(f, ".network"),
            Self::Tags => write!(f, ".tags"),
            Self::Client(client_id, client_loc) => write!(f, ".clients.{client_id}{client_loc}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HubClientLoc {
    Root,
    PublicKey,
    Ip,
    Tags,
    Service(Identifier, ServiceLoc),
}

impl Display for HubClientLoc {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    fn platform_paths() {
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::Platform(PlatformLoc::Root)).to_string(),
            "nodes.Home.platform"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Platform(PlatformLoc::Concern(Concern::WireGuard))
            )
            .to_string(),
            "nodes.Home.platform.wireguard"
        );
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::Platform(PlatformLoc::Interfaces))
                .to_string(),
            "nodes.Home.platform.interfaces"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Platform(PlatformLoc::Interface(id("lan")))
            )
            .to_string(),
            "nodes.Home.platform.interfaces.lan"
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
    fn device_service_path() {
        // The deepest path in the tree — the shape most prone to a copy-paste slip
        // when hand-writing the nested variants.
        let loc = ConfigLocation::Node(
            id("Home"),
            NodeLoc::Zone(
                id("lan"),
                ZoneLoc::Device(
                    id("printer"),
                    DeviceLoc::Service(id("ssh"), ServiceLoc::Port),
                ),
            ),
        );
        assert_eq!(
            loc.to_string(),
            "nodes.Home.zones.lan.devices.printer.services.ssh.port"
        );
    }

    #[test]
    fn hub_paths() {
        assert_eq!(
            ConfigLocation::Node(id("Home"), NodeLoc::Hub(HubLoc::Network)).to_string(),
            "nodes.Home.hub.network"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Hub(HubLoc::Client(
                    id("camera"),
                    HubClientLoc::Service(id("rtsp"), ServiceLoc::Port)
                ))
            )
            .to_string(),
            "nodes.Home.hub.clients.camera.services.rtsp.port"
        );
        assert_eq!(
            ConfigLocation::Node(
                id("Home"),
                NodeLoc::Hub(HubLoc::Client(id("camera"), HubClientLoc::Root))
            )
            .to_string(),
            "nodes.Home.hub.clients.camera"
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
    }
}
