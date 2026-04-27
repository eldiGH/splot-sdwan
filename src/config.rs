use std::{
    collections::{self, HashMap, HashSet},
    fs::File,
    hash::Hash,
    net::Ipv4Addr,
    ops::Deref,
};

use serde::Deserialize;

use crate::{
    protocols::Protocols,
    types::{ip::IpSubnet, mac::MacAddress},
};

#[derive(Debug)]
pub struct OneOrMany<T>(pub Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper<T> {
            One(T),
            Many(Vec<T>),
        }

        Helper::deserialize(deserializer).map(|h| match h {
            Helper::One(x) => OneOrMany(vec![x]),
            Helper::Many(xs) => OneOrMany(xs),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OneOrManyUnique<T>(pub HashSet<T>);

impl<T> Into<HashSet<T>> for OneOrManyUnique<T> {
    fn into(self) -> HashSet<T> {
        self.0
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
pub struct NodeService {
    pub port: String,
    pub proto: OneOrManyUnique<Protocols>,
    pub allow_from: Option<OneOrManyUnique<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeLanDevice {
    pub ip: Ipv4Addr,
    pub macs: Option<OneOrManyUnique<MacAddress>>,
    pub tags: Option<OneOrManyUnique<String>>,
    pub services: Option<HashMap<String, NodeService>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeVpnInterfaceClient {
    pub public_key: String,
    pub ip: Ipv4Addr,
    pub tags: Option<OneOrManyUnique<String>>,
    pub services: Option<HashMap<String, NodeService>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NodeVpnInterfaceRaw {
    pub listen_port: u16,
    pub address: IpSubnet,
    pub tags: Option<OneOrManyUnique<String>>,
    pub clients: HashMap<String, NodeVpnInterfaceClient>,
}

#[derive(Deserialize, Debug)]
#[serde(from = "NodeVpnInterfaceRaw")]
pub struct NodeVpnInterface {
    pub listen_port: u16,
    pub address: IpSubnet,
    pub ip: Ipv4Addr,
    pub subnet: IpSubnet,
    pub tags: Option<OneOrManyUnique<String>>,
    pub clients: HashMap<String, NodeVpnInterfaceClient>,
}

impl From<NodeVpnInterfaceRaw> for NodeVpnInterface {
    fn from(value: NodeVpnInterfaceRaw) -> Self {
        Self {
            address: value.address,
            ip: value.address.ip(),
            subnet: value.address.network(),
            clients: value.clients,
            listen_port: value.listen_port,
            tags: value.tags,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawNodeLan {
    pub address: IpSubnet,
    pub devices: Option<HashMap<String, NodeLanDevice>>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawNodeLan")]
pub struct NodeLan {
    pub address: IpSubnet,
    pub devices: Option<HashMap<String, NodeLanDevice>>,
    pub ip: Ipv4Addr,
    pub subnet: IpSubnet,
}

impl From<RawNodeLan> for NodeLan {
    fn from(value: RawNodeLan) -> Self {
        NodeLan {
            address: value.address,
            devices: value.devices,
            subnet: value.address.network(),
            ip: value.address.ip(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub public_key: String,
    pub endpoint: Ipv4Addr,
    pub listen_port: u16,
    pub mesh_ip: IpSubnet,
    pub lan: NodeLan,
    pub vpn_interfaces: Option<HashMap<String, NodeVpnInterface>>,
    pub tags: Option<OneOrManyUnique<String>>,
    pub services: Option<HashMap<String, NodeService>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub nodes: HashMap<String, Node>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Parse(e)
    }
}

impl Config {
    pub fn parse_file(path: &str) -> Result<Self, ConfigError> {
        let file = File::open(path)?;

        let config = serde_json::from_reader(file)?;

        Ok(config)
    }

    pub fn find_node_name_by_public_key(&self, pubkey: &str) -> Option<String> {
        for (name, node) in &self.nodes {
            if node.public_key == pubkey {
                return Some(name.clone());
            }
        }

        None
    }
}
