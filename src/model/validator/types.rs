use std::{fmt, net::Ipv4Addr};

use crate::{
    consts,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::ConfigLocation,
        identifier::Identifier,
        ip::{Ipv4Network, ReservedAddress},
        port::PortOrRange,
    },
};

pub enum ValidationError {
    // names
    GlobalNameCollision {
        name: Identifier,
        at: ConfigLocation,
    },
    LocalShadowsGlobal {
        name: Identifier,
        at: ConfigLocation,
    },
    LocalNameCollision {
        name: Identifier,
        at: ConfigLocation,
    },
    InvalidPrefix {
        name: Identifier,
        prefix: String,
        at: ConfigLocation,
    },
    ReservedName {
        name: Identifier,
        at: ConfigLocation,
    },

    // tags
    TagWithNameCollision {
        tag: Identifier,
        at: ConfigLocation,
    },

    // references
    UnknownRef {
        reference: AllowFromRef,
        at: ConfigLocation,
    },

    // networks
    IpOutsideSubnet {
        ip: Ipv4Addr,
        network: Ipv4Network,
        at: ConfigLocation,
    },
    ReservedHostAddress {
        ip: Ipv4Addr,
        network: Ipv4Network,
        kind: ReservedAddress,
        at: ConfigLocation,
    },
    NetworkCollision {
        network: Ipv4Network,
        conflicting_with: Ipv4Network,
        at: ConfigLocation,
    },
    HubOutsideMeshNetwork {
        network: Ipv4Network,
        mesh_network: Ipv4Network,
        at: ConfigLocation,
    },
    MeshIpInHubNetwork {
        ip: Ipv4Addr,
        hub: ConfigLocation,
        at: ConfigLocation,
    },
    IpCollision {
        ip: Ipv4Addr,
        at: ConfigLocation,
        with: ConfigLocation,
    },
    NodeClientManyZones {
        zone_name: Identifier,
        existing_zone: ConfigLocation,
        at: ConfigLocation,
    },

    // entities
    MacMissing {
        at: ConfigLocation,
    },

    PublicKeyMissing {
        at: ConfigLocation,
    },

    NodeMissing {
        node_name: Identifier,
        at: ConfigLocation,
    },

    DuplicatePublicKey {
        at: ConfigLocation,
        with: ConfigLocation,
    },

    NodeNetworkMissing {
        node_name: Identifier,
        network_name: Identifier,
        at: ConfigLocation,
    },

    // ports
    PortCollision {
        port: PortOrRange,
        at: ConfigLocation,
        with: ConfigLocation,
    },

    // wan
    InvalidWanVia {
        node_name: Identifier,
        at: ConfigLocation,
    },

    WanViaNodeNoWanZone {
        node_name: Identifier,
        at: ConfigLocation,
    },

    WanViaQualifiedOnNonClient {
        at: ConfigLocation,
    },

    WanViaNetworkMissing {
        node: Identifier,
        network: Identifier,
        at: ConfigLocation,
    },

    WanViaClientNotOnNetwork {
        node: Identifier,
        network: Identifier,
        at: ConfigLocation,
    },

    WanViaUnreachable {
        node: Identifier,
        at: ConfigLocation,
    },

    WanZoneNameCollision {
        wan_zone: Identifier,
        with: ConfigLocation,
        at: ConfigLocation,
    },

    WanZoneReservedName {
        wan_zone: Identifier,
        at: ConfigLocation,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlobalNameCollision { name, at } => {
                write!(
                    f,
                    "{at}: name '{name}' is already used as another global name (node, client, or tag)"
                )
            }
            Self::LocalShadowsGlobal { name, at } => write!(
                f,
                "{at}: local name {name} conflicts with global {name} - rename one to avoid ambiguity"
            ),
            Self::LocalNameCollision { name, at } => {
                write!(f, "{at}: name '{name}' is already used in the same node")
            }
            Self::InvalidPrefix { name, prefix, at } => {
                write!(f, "{at}: name '{name}' uses reserved prefix '{prefix}'")
            }
            Self::ReservedName { name, at } => write!(
                f,
                "{at}: name '{name}' is reserved on every node: splot gives it a meaning of its own (e.g. '{{Node}}.{}' is the node's hub network)",
                consts::HUB_NAME
            ),
            Self::TagWithNameCollision { tag, at } => {
                write!(
                    f,
                    "{at}: tag '{tag}' collides with a name used elsewhere in the global namespace"
                )
            }
            Self::UnknownRef { reference, at } => {
                write!(f, "{at}: unknown identifier '{reference}'")
            }
            Self::IpOutsideSubnet { ip, network, at } => {
                write!(f, "{at}: IP {ip} is outside subnet {network}")
            }
            Self::ReservedHostAddress {
                ip,
                network,
                kind,
                at,
            } => {
                write!(
                    f,
                    "{at}: IP {ip} is the {kind} address of {network} and can't be assigned to a host"
                )
            }
            Self::NetworkCollision {
                network,
                conflicting_with,
                at,
            } => {
                write!(
                    f,
                    "{at}: subnet {network} overlaps with another subnet {conflicting_with}"
                )
            }
            Self::HubOutsideMeshNetwork {
                network,
                mesh_network,
                at,
            } => write!(
                f,
                "{at}: hub network {network} must lie inside meshNetwork {mesh_network}"
            ),
            Self::MeshIpInHubNetwork { ip, hub, at } => write!(
                f,
                "{at}: mesh IP {ip} lies inside the hub network at {hub} - a hub network is routed to its node as a whole, so it can't hold another peer's address"
            ),
            Self::IpCollision { ip, at, with } => {
                write!(f, "{at}: IP {ip} is already used at {with}")
            }
            Self::NodeClientManyZones {
                zone_name,
                existing_zone,
                at,
            } => {
                write!(
                    f,
                    "{at}: client has IP on zone '{zone_name}', but already has an IP on another zone at {existing_zone} (max one zone per (client, node))"
                )
            }
            Self::MacMissing { at } => {
                write!(
                    f,
                    "{at}: client has zone IPs but no macs — MAC required for DHCP lease generation"
                )
            }
            Self::PublicKeyMissing { at } => {
                write!(f, "{at}: public key required (client has a mesh IP)")
            }
            Self::NodeMissing { node_name, at } => {
                write!(f, "{at}: node '{node_name}' does not exist")
            }
            Self::DuplicatePublicKey { at, with } => write!(
                f,
                "{at}: public key is already used at {with} - every node and client needs its own key"
            ),
            Self::NodeNetworkMissing {
                node_name,
                network_name,
                at,
            } => {
                write!(
                    f,
                    "{at}: node '{node_name}' has no network named '{network_name}'"
                )
            }
            Self::PortCollision { port, at, with } => {
                write!(f, "{at}: port {port} collides with {with}")
            }
            Self::InvalidWanVia { node_name, at } => {
                write!(f, "{at}: unknown node '{node_name}'")
            }
            Self::WanViaNodeNoWanZone { node_name, at } => {
                write!(f, "{at}: node '{node_name}' does not have wanZone defined")
            }
            Self::WanViaQualifiedOnNonClient { at } => write!(
                f,
                "{at}: qualified wan target form ({{Node}}.{{Network}}) is only allowed on services hosted by a global client — node/device services have a single unambiguous target and don't need disambiguation"
            ),
            Self::WanViaClientNotOnNetwork { node, network, at } => write!(
                f,
                "{at}: qualified wan target '{node}.{network}' requires this client to have an IP at ips.{node}.{network} — none declared"
            ),
            Self::WanViaNetworkMissing { node, network, at } => write!(
                f,
                "{at}: qualified wan target references network '{network}' on node '{node}', but no such zone exists on that node"
            ),
            Self::WanViaUnreachable { node, at } => write!(
                f,
                "{at}: client has no reachable address on node '{node}' (no meshIp, no zone IP on this node). Either declare an IP for this client on the node, or use a different wan.via target"
            ),
            Self::WanZoneNameCollision { wan_zone, at, with } => write!(
                f,
                "{at}: wanZone '{wan_zone}' collides with another zone at {with} — wanZone must not match any zone or the splot-managed mesh interface on the same node"
            ),
            Self::WanZoneReservedName { wan_zone, at } => write!(
                f,
                "{at}: wanZone '{wan_zone}' uses the name reserved for the splot-managed mesh interface ('{}')",
                consts::MESH_INTERFACE_NAME
            ),
        }
    }
}

impl ValidationError {
    pub fn path(&self) -> &ConfigLocation {
        match self {
            Self::GlobalNameCollision { at, .. } => at,
            Self::InvalidPrefix { at, .. } => at,
            Self::ReservedName { at, .. } => at,
            Self::InvalidWanVia { at, .. } => at,
            Self::IpCollision { at, .. } => at,
            Self::IpOutsideSubnet { at, .. } => at,
            Self::ReservedHostAddress { at, .. } => at,
            Self::LocalNameCollision { at, .. } => at,
            Self::MacMissing { at } => at,
            Self::NetworkCollision { at, .. } => at,
            Self::HubOutsideMeshNetwork { at, .. } => at,
            Self::MeshIpInHubNetwork { at, .. } => at,
            Self::NodeClientManyZones { at, .. } => at,
            Self::NodeMissing { at, .. } => at,
            Self::DuplicatePublicKey { at, .. } => at,
            Self::NodeNetworkMissing { at, .. } => at,
            Self::PortCollision { at, .. } => at,
            Self::PublicKeyMissing { at, .. } => at,
            Self::TagWithNameCollision { at, .. } => at,
            Self::UnknownRef { at, .. } => at,
            Self::LocalShadowsGlobal { at, .. } => at,
            Self::WanViaNodeNoWanZone { at, .. } => at,
            Self::WanViaQualifiedOnNonClient { at, .. } => at,
            Self::WanViaClientNotOnNetwork { at, .. } => at,
            Self::WanViaNetworkMissing { at, .. } => at,
            Self::WanViaUnreachable { at, .. } => at,
            Self::WanZoneNameCollision { at, .. } => at,
            Self::WanZoneReservedName { at, .. } => at,
        }
    }
}

pub enum ValidationWarning {
    // entities
    UnusedMac { at: ConfigLocation },

    UnusedPublicKey { at: ConfigLocation },

    UnreachableClient { at: ConfigLocation },

    // references
    UnreachableService { at: ConfigLocation },

    // wan
    UnusedWanZone { at: ConfigLocation },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedMac { at } => write!(
                f,
                "{at}: macs are declared but client has no zone IPs that would use them"
            ),
            Self::UnusedPublicKey { at } => {
                write!(f, "{at}: publicKey is declared but client has no mesh IP")
            }
            Self::UnreachableClient { at } => {
                write!(f, "{at}: client has no IPs anywhere — nothing routes to it")
            }
            Self::UnreachableService { at } => write!(
                f,
                "{at}: service has neither 'allowFrom' nor 'wan' — no source can reach it"
            ),
            Self::UnusedWanZone { at } => write!(
                f,
                "{at}: wanZone is declared but no service exposes this node in 'wan.via' — either reference this node from a service's wan.via, or remove wanZone"
            ),
        }
    }
}

impl ValidationWarning {
    pub fn path(&self) -> &ConfigLocation {
        match self {
            Self::UnreachableClient { at } => at,
            Self::UnreachableService { at } => at,
            Self::UnusedMac { at } => at,
            Self::UnusedPublicKey { at } => at,
            Self::UnusedWanZone { at } => at,
        }
    }
}

#[derive(Default)]
pub struct ValidationReport {
    pub warnings: Vec<ValidationWarning>,
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn sort(&mut self) {
        self.errors.sort_by(|a, b| a.path().cmp(b.path()));
        self.warnings.sort_by(|a, b| a.path().cmp(b.path()));
    }
}
