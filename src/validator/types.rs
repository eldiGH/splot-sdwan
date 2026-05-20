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
    InvalidTagName {
        tag: Identifier,
        at: ConfigPath,
    },
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

    NodeDoesNotExposeWan {
        node_name: Identifier,
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
            Self::InvalidTagName { tag, at } => {
                write!(
                    f,
                    "{at}: invalid tag '{tag}' — tags follow the same rules as names"
                )
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
            Self::NodeDoesNotExposeWan { node_name, at } => {
                write!(
                    f,
                    "{at}: node '{node_name}' has no 'wanZone' declared — cannot expose services on its WAN"
                )
            }
        }
    }
}

impl ValidationError {
    pub fn path(&self) -> &ConfigPath {
        match self {
            Self::GlobalNameCollision { at, .. } => at,
            Self::InvalidPrefix { at, .. } => at,
            Self::InvalidTagName { at, .. } => at,
            Self::InvalidWanVia { at, .. } => at,
            Self::IpCollision { at, .. } => at,
            Self::IpOutsideSubnet { at, .. } => at,
            Self::LocalNameCollision { at, .. } => at,
            Self::MacMissing { at } => at,
            Self::NetworkCollision { at, .. } => at,
            Self::NodeClientManyZones { at, .. } => at,
            Self::NodeDoesNotExposeWan { at, .. } => at,
            Self::NodeMissing { at, .. } => at,
            Self::NodeNetworkMissing { at, .. } => at,
            Self::PortCollision { at, .. } => at,
            Self::PublicKeyMissing { at, .. } => at,
            Self::TagWithNameCollision { at, .. } => at,
            Self::UnknownRef { at, .. } => at,
            Self::LocalShadowsGlobal { at, .. } => at,
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
