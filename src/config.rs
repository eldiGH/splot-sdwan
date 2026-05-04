use std::{
    collections::{self, HashMap, HashSet},
    fmt::Display,
    fs::File,
    hash::Hash,
    net::Ipv4Addr,
    ops::Deref,
};

use serde::Deserialize;

use crate::{
    protocol::Protocol,
    types::{
        ip::{Ipv4Interface, Ipv4Network},
        mac::MacAddress,
    },
};

#[derive(Debug, Clone)]
pub struct OneOrManyUnique<T>(pub HashSet<T>);

impl<T> Default for OneOrManyUnique<T> {
    fn default() -> Self {
        Self(HashSet::new())
    }
}

impl<T> From<OneOrManyUnique<T>> for HashSet<T> {
    fn from(value: OneOrManyUnique<T>) -> Self {
        value.0
    }
}

impl<T> Deref for OneOrManyUnique<T> {
    type Target = HashSet<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a OneOrManyUnique<T> {
    type Item = &'a T;
    type IntoIter = collections::hash_set::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, T: Deserialize<'de> + Hash + Eq> Deserialize<'de> for OneOrManyUnique<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        #[serde(bound = "T: Deserialize<'de> + Hash + Eq")]
        enum Helper<T> {
            One(T),
            Many(HashSet<T>),
        }

        Helper::deserialize(deserializer).map(|h| match h {
            Helper::One(x) => OneOrManyUnique(HashSet::from([x])),
            Helper::Many(xs) => OneOrManyUnique(xs),
        })
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub port: String,
    pub proto: OneOrManyUnique<Protocol>,

    #[serde(default)]
    pub allow_from: OneOrManyUnique<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeZoneDevice {
    pub ip: Ipv4Addr,

    #[serde(default)]
    pub macs: OneOrManyUnique<MacAddress>,
    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
    #[serde(default)]
    pub services: HashMap<String, Service>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeVpnInterfaceClient {
    pub public_key: String,
    pub ip: Ipv4Addr,

    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
    #[serde(default)]
    pub services: HashMap<String, Service>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeVpnInterface {
    pub listen_port: u16,
    pub address: Ipv4Interface,
    pub clients: HashMap<String, NodeVpnInterfaceClient>,

    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeZone {
    pub address: Option<Ipv4Interface>,

    #[serde(default)]
    pub devices: HashMap<String, NodeZoneDevice>,
    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub public_key: String,
    pub endpoint: Ipv4Addr,
    pub listen_port: u16,
    pub mesh_ip: Ipv4Addr,

    #[serde(default)]
    pub vpn_interfaces: HashMap<String, NodeVpnInterface>,
    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
    #[serde(default)]
    pub services: HashMap<String, Service>,
    #[serde(default)]
    pub zones: HashMap<String, NodeZone>,
}

pub enum ZoneOrVpnInterface<'a> {
    Zone(&'a NodeZone),
    VpnInterface(&'a NodeVpnInterface),
}

impl ZoneOrVpnInterface<'_> {
    pub fn address(&self) -> Option<Ipv4Interface> {
        match self {
            Self::VpnInterface(vpn_interface) => Some(vpn_interface.address),
            Self::Zone(zone) => zone.address,
        }
    }
}

impl Node {
    pub fn network_for_ip(&self, ip: Ipv4Addr) -> Option<(&str, Ipv4Interface)> {
        self.zones
            .iter()
            .filter_map(|(zone_name, zone)| {
                zone.address.map(|address| (zone_name.as_str(), address))
            })
            .chain(
                self.vpn_interfaces
                    .iter()
                    .map(|(vpn_interface_name, vpn_interface)| {
                        (vpn_interface_name.as_str(), vpn_interface.address)
                    }),
            )
            .find(|(_, address)| address.is_in_same_network(ip))
    }

    pub fn network_by_name(&self, name: &str) -> Option<ZoneOrVpnInterface<'_>> {
        self.zones
            .get(name)
            .map(ZoneOrVpnInterface::Zone)
            .or_else(|| {
                self.vpn_interfaces
                    .get(name)
                    .map(ZoneOrVpnInterface::VpnInterface)
            })
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
    pub ips: HashMap<String, HashMap<String, Ipv4Addr>>,
    #[serde(default)]
    pub services: HashMap<String, Service>,
    #[serde(default)]
    pub tags: OneOrManyUnique<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub mesh_network: Ipv4Network,
    pub nodes: HashMap<String, Node>,

    #[serde(default)]
    pub clients: HashMap<String, Client>,
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

    pub fn find_node_name_by_public_key(&self, pubkey: &str) -> Option<&str> {
        self.nodes
            .iter()
            .find_map(|(name, node)| (node.public_key == pubkey).then_some(name.as_str()))
    }
}
