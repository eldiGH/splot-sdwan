use std::{collections::HashMap, fmt::Display, fs::File, iter, net::Ipv4Addr};

use serde::Deserialize;

use crate::{
    protocol::Protocol,
    types::{
        allow_from_ref::AllowFromRef,
        identifier::{Identifier, NestedIdentifier},
        ip::{Ipv4Interface, Ipv4Network},
        mac::MacAddress,
        port::{Port, ServicePort},
        schema_helpers::OneOrManyUnique,
        wan_via_target::{WanViaTarget, WanViaTargets},
        zone_ref::ZoneRef,
    },
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServiceWan {
    pub via: WanViaTargets,

    #[serde(default)]
    pub sources: OneOrManyUnique<Ipv4Network>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub port: ServicePort,
    pub proto: OneOrManyUnique<Protocol>,

    #[serde(default)]
    pub allow_from: OneOrManyUnique<AllowFromRef>,

    pub wan: Option<ServiceWan>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeZoneDevice {
    pub ip: Ipv4Addr,
    pub macs: OneOrManyUnique<MacAddress>,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: HashMap<Identifier, Service>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeVpnInterfaceClient {
    pub public_key: String,
    pub ip: Ipv4Addr,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: HashMap<Identifier, Service>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeVpnInterface {
    pub listen_port: Port,
    pub address: Ipv4Interface,
    pub clients: HashMap<Identifier, NodeVpnInterfaceClient>,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeZone {
    pub address: Ipv4Interface,

    #[serde(default)]
    pub devices: HashMap<Identifier, NodeZoneDevice>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub public_key: String,
    pub endpoint: Ipv4Addr,
    pub listen_port: Port,
    pub mesh_ip: Ipv4Addr,

    #[serde(default)]
    pub vpn_interfaces: HashMap<Identifier, NodeVpnInterface>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: HashMap<Identifier, Service>,
    #[serde(default)]
    pub zones: HashMap<Identifier, NodeZone>,

    pub wan_zone: Option<Identifier>,
}

pub enum ZoneOrVpnInterface<'a> {
    Zone(&'a NodeZone),
    VpnInterface(&'a NodeVpnInterface),
}

impl ZoneOrVpnInterface<'_> {
    pub fn address(&self) -> Ipv4Interface {
        match self {
            Self::VpnInterface(vpn_interface) => vpn_interface.address,
            Self::Zone(zone) => zone.address,
        }
    }
}

impl Node {
    pub fn network_for_ip(&self, ip: Ipv4Addr) -> Option<(&Identifier, Ipv4Interface)> {
        self.zones
            .iter()
            .map(|(zone_name, zone)| (zone_name, zone.address))
            .chain(
                self.vpn_interfaces
                    .iter()
                    .map(|(vpn_interface_name, vpn_interface)| {
                        (vpn_interface_name, vpn_interface.address)
                    }),
            )
            .find(|(_, address)| address.is_in_same_network(ip))
    }

    pub fn network_by_name(&self, name: &Identifier) -> Option<ZoneOrVpnInterface<'_>> {
        self.zones
            .get(name)
            .map(ZoneOrVpnInterface::Zone)
            .or_else(|| {
                self.vpn_interfaces
                    .get(name)
                    .map(ZoneOrVpnInterface::VpnInterface)
            })
    }

    pub fn addresses(&self) -> impl Iterator<Item = Ipv4Interface> {
        let zone_networks = self.zones.values().map(|zone| zone.address);

        let vpn_interfaces_networks = self
            .vpn_interfaces
            .values()
            .map(|vpn_interface| vpn_interface.address);

        zone_networks.chain(vpn_interfaces_networks)
    }

    pub fn networks(&self) -> impl Iterator<Item = Ipv4Network> {
        self.addresses().map(|address| address.network())
    }

    pub fn host_interfaces(&self) -> impl Iterator<Item = Ipv4Interface> {
        let mesh = Ipv4Interface::host(self.mesh_ip);
        iter::once(mesh).chain(self.addresses())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub mesh_ip: Option<Ipv4Addr>,
    pub public_key: Option<String>,

    #[serde(default)]
    pub macs: OneOrManyUnique<MacAddress>,
    #[serde(default)]
    pub ips: HashMap<Identifier, HashMap<Identifier, Ipv4Addr>>,
    #[serde(default)]
    pub services: HashMap<Identifier, Service>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

pub enum WanResolveError {
    AmbiguousVpn { candidates: Vec<Identifier> },
    Unreachable,
    QualifiedNetworkMissing { network: Identifier },
    QualifiedClientNotOnNetwork { network: Identifier },
}

pub struct WanResolution {
    pub dest_ip: Ipv4Addr,
    pub dest_zone: ZoneRef,
}

impl Client {
    pub fn network_by_name(
        &self,
        node_name: &Identifier,
        network_name: &Identifier,
    ) -> Option<Ipv4Addr> {
        self.ips.get(node_name)?.get(network_name).copied()
    }

    fn resolve_wan(
        &self,
        node_name: &Identifier,
        node: &Node,
    ) -> Result<WanResolution, WanResolveError> {
        if let Some(mesh_ip) = self.mesh_ip {
            return Ok(WanResolution {
                dest_ip: mesh_ip,
                dest_zone: ZoneRef::Mesh,
            });
        }

        let Some(node_networks) = self.ips.get(node_name) else {
            return Err(WanResolveError::Unreachable);
        };

        let mut zone_ip: Option<(&Identifier, Ipv4Addr)> = None;
        let mut vpn_interface_candidates: Vec<(&Identifier, Ipv4Addr)> = Vec::new();

        for (network_name, ip) in node_networks {
            match node.network_by_name(network_name) {
                Some(ZoneOrVpnInterface::Zone(_)) => zone_ip = Some((network_name, *ip)),
                Some(ZoneOrVpnInterface::VpnInterface(_)) => {
                    vpn_interface_candidates.push((network_name, *ip))
                }

                None => {}
            }
        }

        if let Some((zone_name, zone_ip)) = zone_ip {
            return Ok(WanResolution {
                dest_ip: zone_ip,
                dest_zone: ZoneRef::Named(zone_name.clone()),
            });
        }

        match vpn_interface_candidates.as_slice() {
            [] => Err(WanResolveError::Unreachable),
            [(vpn_interface_name, ip)] => Ok(WanResolution {
                dest_zone: ZoneRef::Named((*vpn_interface_name).clone()),
                dest_ip: *ip,
            }),
            _ => Err(WanResolveError::AmbiguousVpn {
                candidates: vpn_interface_candidates
                    .iter()
                    .map(|(vpn_interface_name, _)| (*vpn_interface_name).clone())
                    .collect(),
            }),
        }
    }

    fn resolve_wan_qualified(
        &self,
        node_name: &Identifier,
        local_name: &Identifier,
        node: &Node,
    ) -> Result<WanResolution, WanResolveError> {
        if node.network_by_name(local_name).is_none() {
            return Err(WanResolveError::QualifiedNetworkMissing {
                network: local_name.clone(),
            });
        }

        let ip = self
            .ips
            .get(node_name)
            .and_then(|networks| networks.get(local_name))
            .ok_or(WanResolveError::QualifiedClientNotOnNetwork {
                network: local_name.clone(),
            })?;

        Ok(WanResolution {
            dest_ip: *ip,
            dest_zone: ZoneRef::Named(local_name.clone()),
        })
    }

    pub fn resolve_wan_target(
        &self,
        via: &WanViaTarget,
        node: &Node,
    ) -> Result<WanResolution, WanResolveError> {
        match via {
            WanViaTarget::Bare(node_name) => self.resolve_wan(node_name, node),
            WanViaTarget::Qualified(NestedIdentifier {
                node: node_name,
                local,
            }) => self.resolve_wan_qualified(node_name, local, node),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub mesh_network: Ipv4Network,
    pub nodes: HashMap<Identifier, Node>,

    #[serde(default)]
    pub clients: HashMap<Identifier, Client>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_yml::Error),
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<serde_yml::Error> for ConfigError {
    fn from(e: serde_yml::Error) -> Self {
        ConfigError::Parse(e)
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Parse(error) => error.fmt(f),
        }
    }
}

impl Config {
    pub fn parse_file(path: &str) -> Result<Self, ConfigError> {
        log::info!("Loading config from '{path}'");

        let file = File::open(path)?;
        let config: Self = serde_yml::from_reader(file)?;

        log::info!(
            "Config loaded: {} node(s), {} client(s), mesh network {}",
            config.nodes.len(),
            config.clients.len(),
            config.mesh_network,
        );

        Ok(config)
    }

    pub fn find_node_name_by_public_key(&self, pubkey: &str) -> Option<&Identifier> {
        self.nodes
            .iter()
            .find_map(|(name, node)| (node.public_key == pubkey).then_some(name))
    }
}
