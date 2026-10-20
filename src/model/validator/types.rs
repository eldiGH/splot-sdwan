use std::{fmt, net::Ipv4Addr};

use crate::{
    consts,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::ConfigLocation,
        identifier::Identifier,
        ip::{Ipv4Network, ReservedAddress},
        platform::{Concern, Os},
        port::PortOrRange,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    // platform
    #[error(
        "{at}: {concern} left out - a {os} node names the program behind every concern, or none to leave it alone"
    )]
    ConcernMissing {
        concern: Concern,
        os: Os,
        at: ConfigLocation,
    },
    #[error(
        "{at}: splot can't manage {concern} with {program} on {os} - there it's {choices}, or none"
    )]
    UnsupportedProgram {
        concern: Concern,
        program: String,
        os: Os,
        choices: String,
        at: ConfigLocation,
    },

    // names
    #[error("{at}: name '{name}' is already used as another global name (node, client, or tag)")]
    GlobalNameCollision {
        name: Identifier,
        at: ConfigLocation,
    },
    #[error("{at}: local name {name} conflicts with global {name} - rename one to avoid ambiguity")]
    LocalShadowsGlobal {
        name: Identifier,
        at: ConfigLocation,
    },
    #[error("{at}: name '{name}' is already used in the same node")]
    LocalNameCollision {
        name: Identifier,
        at: ConfigLocation,
    },
    #[error("{at}: name '{name}' uses reserved prefix '{prefix}'")]
    InvalidPrefix {
        name: Identifier,
        prefix: String,
        at: ConfigLocation,
    },
    #[error(
        "{at}: name '{name}' is reserved on every node: splot gives it a meaning of its own (e.g. '{{Node}}.{}' is the node's hub network)",
        consts::HUB_NAME
    )]
    ReservedName {
        name: Identifier,
        at: ConfigLocation,
    },

    // tags
    #[error("{at}: tag '{tag}' collides with a name used elsewhere in the global namespace")]
    TagWithNameCollision { tag: Identifier, at: ConfigLocation },

    // references
    #[error("{at}: unknown identifier '{reference}'")]
    UnknownRef {
        reference: AllowFromRef,
        at: ConfigLocation,
    },

    // networks
    #[error("{at}: IP {ip} is outside subnet {network}")]
    IpOutsideSubnet {
        ip: Ipv4Addr,
        network: Ipv4Network,
        at: ConfigLocation,
    },
    #[error("{at}: IP {ip} is the {kind} address of {network} and can't be assigned to a host")]
    ReservedHostAddress {
        ip: Ipv4Addr,
        network: Ipv4Network,
        kind: ReservedAddress,
        at: ConfigLocation,
    },
    #[error("{at}: subnet {network} overlaps with another subnet {conflicting_with}")]
    NetworkCollision {
        network: Ipv4Network,
        conflicting_with: Ipv4Network,
        at: ConfigLocation,
    },
    #[error("{at}: hub network {network} must lie inside meshNetwork {mesh_network}")]
    HubOutsideMeshNetwork {
        network: Ipv4Network,
        mesh_network: Ipv4Network,
        at: ConfigLocation,
    },
    #[error(
        "{at}: mesh IP {ip} lies inside the hub network at {hub} - a hub network is routed to its node as a whole, so it can't hold another peer's address"
    )]
    MeshIpInHubNetwork {
        ip: Ipv4Addr,
        hub: ConfigLocation,
        at: ConfigLocation,
    },
    #[error("{at}: IP {ip} is already used at {with}")]
    IpCollision {
        ip: Ipv4Addr,
        at: ConfigLocation,
        with: ConfigLocation,
    },
    #[error(
        "{at}: client has IP on zone '{zone_name}', but already has an IP on another zone at {existing_zone} (max one zone per (client, node))"
    )]
    NodeClientManyZones {
        zone_name: Identifier,
        existing_zone: ConfigLocation,
        at: ConfigLocation,
    },

    // entities
    #[error("{at}: client has zone IPs but no macs — MAC required for DHCP lease generation")]
    MacMissing { at: ConfigLocation },

    #[error("{at}: public key required (client has a mesh IP)")]
    PublicKeyMissing { at: ConfigLocation },

    #[error("{at}: node '{node_name}' does not exist")]
    NodeMissing {
        node_name: Identifier,
        at: ConfigLocation,
    },

    #[error("{at}: public key is already used at {with} - every node and client needs its own key")]
    DuplicatePublicKey {
        at: ConfigLocation,
        with: ConfigLocation,
    },

    #[error("{at}: node '{node_name}' has no network named '{network_name}'")]
    NodeNetworkMissing {
        node_name: Identifier,
        network_name: Identifier,
        at: ConfigLocation,
    },

    // endpoints
    #[error(
        "{at}: no node has an endpoint - at least one must, or no node can dial another and the mesh never forms"
    )]
    NoDialableNode { at: ConfigLocation },

    #[error(
        "{at}: the node has a hub but no endpoint - hub clients dial their hub node, so it needs one"
    )]
    HubOnUndialableNode { at: ConfigLocation },

    // ports
    #[error("{at}: port {port} collides with {with}")]
    PortCollision {
        port: PortOrRange,
        at: ConfigLocation,
        with: ConfigLocation,
    },

    // wan
    #[error("{at}: unknown node '{node_name}'")]
    InvalidWanVia {
        node_name: Identifier,
        at: ConfigLocation,
    },

    #[error("{at}: node '{node_name}' does not have wanZone defined")]
    WanViaNodeNoWanZone {
        node_name: Identifier,
        at: ConfigLocation,
    },

    #[error(
        "{at}: qualified wan target form ({{Node}}.{{Network}}) is only allowed on services hosted by a global client — node/device services have a single unambiguous target and don't need disambiguation"
    )]
    WanViaQualifiedOnNonClient { at: ConfigLocation },

    #[error(
        "{at}: qualified wan target references network '{network}' on node '{node}', but no such zone exists on that node"
    )]
    WanViaNetworkMissing {
        node: Identifier,
        network: Identifier,
        at: ConfigLocation,
    },

    #[error(
        "{at}: qualified wan target '{node}.{network}' requires this client to have an IP at ips.{node}.{network} — none declared"
    )]
    WanViaClientNotOnNetwork {
        node: Identifier,
        network: Identifier,
        at: ConfigLocation,
    },

    #[error(
        "{at}: client has no reachable address on node '{node}' (no meshIp, no zone IP on this node). Either declare an IP for this client on the node, or use a different wan.via target"
    )]
    WanViaUnreachable {
        node: Identifier,
        at: ConfigLocation,
    },

    #[error(
        "{at}: wanZone '{wan_zone}' collides with another zone at {with} — wanZone must not match any zone or the splot-managed mesh interface on the same node"
    )]
    WanZoneNameCollision {
        wan_zone: Identifier,
        with: ConfigLocation,
        at: ConfigLocation,
    },

    #[error(
        "{at}: wanZone '{wan_zone}' uses the name reserved for the splot-managed mesh interface ('{}')",
        consts::MESH_INTERFACE_NAME
    )]
    WanZoneReservedName {
        wan_zone: Identifier,
        at: ConfigLocation,
    },
}

impl ValidationError {
    pub fn path(&self) -> &ConfigLocation {
        match self {
            Self::ConcernMissing { at, .. } => at,
            Self::UnsupportedProgram { at, .. } => at,
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
            Self::NoDialableNode { at } => at,
            Self::HubOnUndialableNode { at } => at,
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
    // platform, concerns left alone
    /// What the node's firewall won't do, and whether splot's mesh interface is
    /// there for the operator to put into a zone.
    FirewallLeftAlone {
        node: Identifier,
        /// Services whose `allowFrom` splot would enforce on the node.
        unenforced: Vec<String>,
        /// Services exposed through the node.
        unforwarded: Vec<String>,
        mesh_interface: bool,
        at: ConfigLocation,
    },
    /// The node's firewall has no mesh zone.
    WireGuardLeftAlone {
        node: Identifier,
        /// Services exposed through the node to a host reached over the mesh.
        unforwarded: Vec<String>,
        at: ConfigLocation,
    },

    // entities
    UnusedMac {
        at: ConfigLocation,
    },

    UnusedPublicKey {
        at: ConfigLocation,
    },

    UnreachableClient {
        at: ConfigLocation,
    },

    // references
    UnreachableService {
        at: ConfigLocation,
    },

    // endpoints
    NoDirectTunnel {
        other: Identifier,
        at: ConfigLocation,
    },

    // wan
    UnusedWanZone {
        at: ConfigLocation,
    },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirewallLeftAlone {
                node,
                unenforced,
                unforwarded,
                mesh_interface,
                at,
            } => {
                let mut undone = Vec::new();
                if !unenforced.is_empty() {
                    undone.push(format!(
                        "allowFrom isn't enforced there, your own rules decide who reaches {}",
                        unenforced.join(", ")
                    ));
                }
                if !unforwarded.is_empty() {
                    undone.push(format!(
                        "nothing is forwarded from its WAN to {}",
                        unforwarded.join(", ")
                    ));
                }
                if *mesh_interface {
                    undone.push(
                        "put splot's mesh interface into a zone of yours, and let its listen port in from the WAN"
                            .to_owned(),
                    );
                }
                write!(
                    f,
                    "{at}: splot leaves {node}'s firewall alone - {}",
                    undone.join("; ")
                )
            }
            Self::WireGuardLeftAlone {
                node,
                unforwarded,
                at,
            } => {
                write!(
                    f,
                    "{at}: splot leaves {node}'s WireGuard alone, so its firewall has no mesh zone - mesh traffic arrives in your interface's zone, under your rules"
                )?;
                if !unforwarded.is_empty() {
                    write!(
                        f,
                        "; nothing is forwarded from its WAN to {}, as they're reached over the mesh",
                        unforwarded.join(", ")
                    )?;
                }
                Ok(())
            }
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
            Self::NoDirectTunnel { other, at } => write!(
                f,
                "{at}: neither this node nor '{other}' has an endpoint, so neither can dial the other - they have no direct tunnel"
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
            Self::FirewallLeftAlone { at, .. } => at,
            Self::WireGuardLeftAlone { at, .. } => at,
            Self::UnreachableClient { at } => at,
            Self::UnreachableService { at } => at,
            Self::UnusedMac { at } => at,
            Self::UnusedPublicKey { at } => at,
            Self::NoDirectTunnel { at, .. } => at,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::config_location::NodeLoc;

    #[test]
    fn every_error_message() {
        // Pins what each one says. Values are only placeholders; the locations
        // print the way the config spells them.
        let at = || ConfigLocation::Node("Home".parse().unwrap(), NodeLoc::MeshIp);
        let with = || ConfigLocation::Node("Cabin".parse().unwrap(), NodeLoc::MeshIp);
        let id = |s: &str| -> Identifier { s.parse().unwrap() };
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let network: Ipv4Network = "10.0.0.0/24".parse().unwrap();
        let other: Ipv4Network = "10.1.0.0/16".parse().unwrap();

        let errors = [
            ValidationError::ConcernMissing {
                concern: Concern::Firewall,
                os: Os::Linux,
                at: at(),
            },
            ValidationError::UnsupportedProgram {
                concern: Concern::WireGuard,
                program: "wg-quick".to_owned(),
                os: Os::OpenWrt,
                choices: "netifd".to_owned(),
                at: at(),
            },
            ValidationError::GlobalNameCollision {
                name: id("Home"),
                at: at(),
            },
            ValidationError::LocalShadowsGlobal {
                name: id("Cabin"),
                at: at(),
            },
            ValidationError::LocalNameCollision {
                name: id("lan"),
                at: at(),
            },
            ValidationError::InvalidPrefix {
                name: id("Home_x"),
                prefix: "Home_".to_owned(),
                at: at(),
            },
            ValidationError::ReservedName {
                name: id("hub"),
                at: at(),
            },
            ValidationError::TagWithNameCollision {
                tag: id("Home"),
                at: at(),
            },
            ValidationError::UnknownRef {
                reference: "Home.nas".parse().unwrap(),
                at: at(),
            },
            ValidationError::IpOutsideSubnet {
                ip,
                network,
                at: at(),
            },
            ValidationError::ReservedHostAddress {
                ip,
                network,
                kind: ReservedAddress::Network,
                at: at(),
            },
            ValidationError::NetworkCollision {
                network,
                conflicting_with: other,
                at: at(),
            },
            ValidationError::HubOutsideMeshNetwork {
                network,
                mesh_network: other,
                at: at(),
            },
            ValidationError::MeshIpInHubNetwork {
                ip,
                hub: with(),
                at: at(),
            },
            ValidationError::IpCollision {
                ip,
                at: at(),
                with: with(),
            },
            ValidationError::NodeClientManyZones {
                zone_name: id("iot"),
                existing_zone: with(),
                at: at(),
            },
            ValidationError::MacMissing { at: at() },
            ValidationError::PublicKeyMissing { at: at() },
            ValidationError::NodeMissing {
                node_name: id("Lake"),
                at: at(),
            },
            ValidationError::DuplicatePublicKey {
                at: at(),
                with: with(),
            },
            ValidationError::NodeNetworkMissing {
                node_name: id("Home"),
                network_name: id("iot"),
                at: at(),
            },
            ValidationError::NoDialableNode {
                at: ConfigLocation::Nodes,
            },
            ValidationError::HubOnUndialableNode { at: at() },
            ValidationError::PortCollision {
                port: "22".parse().unwrap(),
                at: at(),
                with: with(),
            },
            ValidationError::InvalidWanVia {
                node_name: id("Lake"),
                at: at(),
            },
            ValidationError::WanViaNodeNoWanZone {
                node_name: id("Home"),
                at: at(),
            },
            ValidationError::WanViaQualifiedOnNonClient { at: at() },
            ValidationError::WanViaNetworkMissing {
                node: id("Home"),
                network: id("iot"),
                at: at(),
            },
            ValidationError::WanViaClientNotOnNetwork {
                node: id("Home"),
                network: id("iot"),
                at: at(),
            },
            ValidationError::WanViaUnreachable {
                node: id("Home"),
                at: at(),
            },
            ValidationError::WanZoneNameCollision {
                wan_zone: id("lan"),
                with: with(),
                at: at(),
            },
            ValidationError::WanZoneReservedName {
                wan_zone: id("mesh"),
                at: at(),
            },
        ];

        let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
        insta::assert_snapshot!(messages.join("\n"));
    }
}
