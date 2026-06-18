use std::{fmt, net::Ipv4Addr};

use crate::types::{
    allow_from_ref::AllowFromRef, identifier::Identifier, ip::Ipv4Network, port::PortOrRange,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigPath(Vec<String>);

impl ConfigPath {
    pub fn new(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(segments.into_iter().map(|item| item.into()).collect())
    }

    pub fn extend(mut self, segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.extend(segments.into_iter().map(|item| item.into()));
        self
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "<root>");
        }

        write!(f, "{}", self.0.join("."))
    }
}

pub enum ValidationError {
    // names
    GlobalNameCollision {
        name: Identifier,
        at: ConfigPath,
    },
    LocalShadowsGlobal {
        name: Identifier,
        at: ConfigPath,
    },
    LocalNameCollision {
        name: Identifier,
        at: ConfigPath,
    },
    InvalidPrefix {
        name: Identifier,
        prefix: String,
        at: ConfigPath,
    },

    // tags
    TagWithNameCollision {
        tag: Identifier,
        at: ConfigPath,
    },

    // references
    UnknownRef {
        reference: AllowFromRef,
        at: ConfigPath,
    },

    // networks
    IpOutsideSubnet {
        ip: Ipv4Addr,
        network: Ipv4Network,
        at: ConfigPath,
    },
    NetworkCollision {
        network: Ipv4Network,
        conflicting_with: Ipv4Network,
        at: ConfigPath,
    },
    IpCollision {
        ip: Ipv4Addr,
        at: ConfigPath,
        with: ConfigPath,
    },
    NodeClientManyZones {
        zone_name: Identifier,
        existing_zone: ConfigPath,
        at: ConfigPath,
    },

    // entities
    MacMissing {
        at: ConfigPath,
    },

    PublicKeyMissing {
        required_for_mesh: bool,
        required_for_vpn_interface: bool,
        at: ConfigPath,
    },

    NodeMissing {
        node_name: Identifier,
        at: ConfigPath,
    },

    NodeNetworkMissing {
        node_name: Identifier,
        network_name: Identifier,
        at: ConfigPath,
    },

    // ports
    PortCollision {
        port: PortOrRange,
        at: ConfigPath,
        with: ConfigPath,
    },

    // wan
    InvalidWanVia {
        node_name: Identifier,
        at: ConfigPath,
    },

    WanViaNodeNoWanZone {
        node_name: Identifier,
        at: ConfigPath,
    },

    WanViaQualifiedOnNonClient {
        at: ConfigPath,
    },

    WanViaNetworkMissing {
        node: Identifier,
        network: Identifier,
        at: ConfigPath,
    },

    WanViaClientNotOnNetwork {
        node: Identifier,
        network: Identifier,
        at: ConfigPath,
    },

    WanViaAmbiguous {
        node: Identifier,
        candidates: Vec<Identifier>,
        at: ConfigPath,
    },

    WanViaUnreachable {
        node: Identifier,
        at: ConfigPath,
    },

    WanZoneNameCollision {
        wan_zone: Identifier,
        with: ConfigPath,
        at: ConfigPath,
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
            Self::PublicKeyMissing {
                required_for_mesh,
                required_for_vpn_interface,
                at,
            } => {
                let reasons: Vec<&str> = [
                    required_for_mesh.then_some("client has a mesh IP"),
                    required_for_vpn_interface.then_some("client has a VPN interface IP"),
                ]
                .into_iter()
                .flatten()
                .collect();
                write!(f, "{at}: public key required ({})", reasons.join(", "))
            }
            Self::NodeMissing { node_name, at } => {
                write!(f, "{at}: node '{node_name}' does not exist")
            }
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
                "{at}: qualified wan target form ({{Node}}.{{Network}}) is only allowed on services hosted by a global client — node/device/vpn-client services have a single unambiguous target and don't need disambiguation"
            ),
            Self::WanViaAmbiguous {
                node,
                candidates,
                at,
            } => {
                let candidates_joined = candidates
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                let first_candidate = candidates
                    .first()
                    .expect("there should always be at least 2 candidates");

                write!(
                    f,
                    "{at}: client is reachable via multiple VPN interfaces on node '{node}' ({candidates_joined}). Use the qualified form (e.g. '{node}.{first_candidate}') to disambiguate"
                )
            }
            Self::WanViaClientNotOnNetwork { node, network, at } => write!(
                f,
                "{at}: qualified wan target '{node}.{network}' requires this client to have an IP at ips.{node}.{network} — none declared"
            ),
            Self::WanViaNetworkMissing { node, network, at } => write!(
                f,
                "{at}: qualified wan target references network '{network}' on node '{node}', but no such zone or VPN interface exists on that node"
            ),
            Self::WanViaUnreachable { node, at } => write!(
                f,
                "{at}: client has no reachable address on node '{node}' (no meshIp, no zone IP, no VPN IP on this node). Either declare an IP for this client on the node, or use a different wan.via target"
            ),
            Self::WanZoneNameCollision { wan_zone, at, with } => write!(
                f,
                "{at}: wanZone '{wan_zone}' collides with another zone at {with} — wanZone must not match any zone, VPN interface, or the splot-managed mesh interface on the same node"
            ),
        }
    }
}

impl ValidationError {
    pub fn path(&self) -> &ConfigPath {
        match self {
            Self::GlobalNameCollision { at, .. } => at,
            Self::InvalidPrefix { at, .. } => at,
            Self::InvalidWanVia { at, .. } => at,
            Self::IpCollision { at, .. } => at,
            Self::IpOutsideSubnet { at, .. } => at,
            Self::LocalNameCollision { at, .. } => at,
            Self::MacMissing { at } => at,
            Self::NetworkCollision { at, .. } => at,
            Self::NodeClientManyZones { at, .. } => at,
            Self::NodeMissing { at, .. } => at,
            Self::NodeNetworkMissing { at, .. } => at,
            Self::PortCollision { at, .. } => at,
            Self::PublicKeyMissing { at, .. } => at,
            Self::TagWithNameCollision { at, .. } => at,
            Self::UnknownRef { at, .. } => at,
            Self::LocalShadowsGlobal { at, .. } => at,
            Self::WanViaNodeNoWanZone { at, .. } => at,
            Self::WanViaQualifiedOnNonClient { at, .. } => at,
            Self::WanViaAmbiguous { at, .. } => at,
            Self::WanViaClientNotOnNetwork { at, .. } => at,
            Self::WanViaNetworkMissing { at, .. } => at,
            Self::WanViaUnreachable { at, .. } => at,
            Self::WanZoneNameCollision { at, .. } => at,
        }
    }
}

pub enum ValidationWarning {
    // entities
    UnusedMac { at: ConfigPath },

    UnusedPublicKey { at: ConfigPath },

    UnreachableClient { at: ConfigPath },

    // references
    UnreachableService { at: ConfigPath },

    // wan
    UnusedWanZone { at: ConfigPath },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedMac { at } => write!(
                f,
                "{at}: macs are declared but client has no zone IPs that would use them"
            ),
            Self::UnusedPublicKey { at } => write!(
                f,
                "{at}: publicKey is declared but client has no mesh IP and no VPN interface IPs"
            ),
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
    pub fn path(&self) -> &ConfigPath {
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
