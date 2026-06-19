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

#[derive(Debug)]
pub enum WanResolveError {
    AmbiguousVpn { candidates: Vec<Identifier> },
    Unreachable,
    QualifiedNetworkMissing { network: Identifier },
    QualifiedClientNotOnNetwork { network: Identifier },
}

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;

    // One node with a zone and two VPN interfaces.
    // Five clients cover every branch of resolve_wan + qualified variants.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
    vpnInterfaces:
      vpn_a:
        listenPort: 51821
        address: 10.8.1.1/24
        clients: {}
      vpn_b:
        listenPort: 51822
        address: 10.8.2.1/24
        clients: {}
clients:
  # has meshIp AND a zone IP; mesh must win
  PhoneWithMesh:
    meshIp: 10.100.0.100
    ips:
      Home:
        lan: 192.168.1.50
  # no meshIp, zone IP only
  ZoneOnly:
    ips:
      Home:
        lan: 192.168.1.60
  # no meshIp, single VPN interface IP
  VpnSingle:
    ips:
      Home:
        vpn_a: 10.8.1.10
  # no meshIp, IPs on two VPN interfaces — ambiguous
  VpnAmbig:
    ips:
      Home:
        vpn_a: 10.8.1.20
        vpn_b: 10.8.2.20
  # no meshIp, no IPs on Home at all
  Nowhere: {}
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn bare(s: &str) -> WanViaTarget {
        s.parse().unwrap()
    }

    fn qualified(node: &str, local: &str) -> WanViaTarget {
        format!("{node}.{local}").parse().unwrap()
    }

    struct Fixture {
        home: Node,
        phone: Client,
        zone_only: Client,
        vpn_single: Client,
        vpn_ambig: Client,
        nowhere: Client,
    }

    impl Fixture {
        fn load() -> Self {
            let cfg = config(FIXTURE);
            let mut nodes = cfg.nodes;
            let mut clients = cfg.clients;
            Self {
                home: nodes.remove(&id("Home")).unwrap(),
                phone: clients.remove(&id("PhoneWithMesh")).unwrap(),
                zone_only: clients.remove(&id("ZoneOnly")).unwrap(),
                vpn_single: clients.remove(&id("VpnSingle")).unwrap(),
                vpn_ambig: clients.remove(&id("VpnAmbig")).unwrap(),
                nowhere: clients.remove(&id("Nowhere")).unwrap(),
            }
        }
    }

    // --- Bare via: priority chain ---

    #[test]
    fn bare_meship_wins_over_zone_ip() {
        let f = Fixture::load();
        let res = f.phone.resolve_wan_target(&bare("Home"), &f.home).unwrap();
        assert_eq!(res.dest_ip.to_string(), "10.100.0.100");
        assert_eq!(res.dest_zone, ZoneRef::Mesh);
    }

    #[test]
    fn bare_zone_ip_when_no_mesh() {
        let f = Fixture::load();
        let res = f
            .zone_only
            .resolve_wan_target(&bare("Home"), &f.home)
            .unwrap();
        assert_eq!(res.dest_ip.to_string(), "192.168.1.60");
        assert_eq!(res.dest_zone, ZoneRef::Named(id("lan")));
    }

    #[test]
    fn bare_single_vpn_ip_when_no_mesh_no_zone() {
        let f = Fixture::load();
        let res = f
            .vpn_single
            .resolve_wan_target(&bare("Home"), &f.home)
            .unwrap();
        assert_eq!(res.dest_ip.to_string(), "10.8.1.10");
        assert_eq!(res.dest_zone, ZoneRef::Named(id("vpn_a")));
    }

    #[test]
    fn bare_ambiguous_vpn_returns_error() {
        let f = Fixture::load();
        let err = f
            .vpn_ambig
            .resolve_wan_target(&bare("Home"), &f.home)
            .unwrap_err();
        assert!(
            matches!(err, WanResolveError::AmbiguousVpn { candidates } if candidates.len() == 2)
        );
    }

    #[test]
    fn bare_unreachable_when_no_ips_on_node() {
        let f = Fixture::load();
        let err = f
            .nowhere
            .resolve_wan_target(&bare("Home"), &f.home)
            .unwrap_err();
        assert!(matches!(err, WanResolveError::Unreachable));
    }

    // --- Qualified via ---

    #[test]
    fn qualified_zone_network_resolves() {
        let f = Fixture::load();
        let res = f
            .zone_only
            .resolve_wan_target(&qualified("Home", "lan"), &f.home)
            .unwrap();
        assert_eq!(res.dest_ip.to_string(), "192.168.1.60");
        assert_eq!(res.dest_zone, ZoneRef::Named(id("lan")));
    }

    #[test]
    fn qualified_vpn_network_resolves() {
        let f = Fixture::load();
        let via = qualified("Home", "vpn_a");
        let res = f.vpn_ambig.resolve_wan_target(&via, &f.home).unwrap();
        assert_eq!(res.dest_ip.to_string(), "10.8.1.20");
        assert_eq!(res.dest_zone, ZoneRef::Named(id("vpn_a")));
    }

    #[test]
    fn qualified_missing_network_on_node() {
        let f = Fixture::load();
        let err = f
            .zone_only
            .resolve_wan_target(&qualified("Home", "missing_net"), &f.home)
            .unwrap_err();
        assert!(matches!(
            err,
            WanResolveError::QualifiedNetworkMissing { network } if network == id("missing_net")
        ));
    }

    #[test]
    fn qualified_client_not_on_network() {
        let f = Fixture::load();
        // ZoneOnly has no vpn_a IP, but vpn_a exists on Home
        let err = f
            .zone_only
            .resolve_wan_target(&qualified("Home", "vpn_a"), &f.home)
            .unwrap_err();
        assert!(matches!(
            err,
            WanResolveError::QualifiedClientNotOnNetwork { network } if network == id("vpn_a")
        ));
    }

    // --- Node helpers ---

    #[test]
    fn node_network_by_name_zone() {
        let f = Fixture::load();
        assert!(matches!(
            f.home.network_by_name(&id("lan")),
            Some(ZoneOrVpnInterface::Zone(_))
        ));
    }

    #[test]
    fn node_network_by_name_vpn() {
        let f = Fixture::load();
        assert!(matches!(
            f.home.network_by_name(&id("vpn_a")),
            Some(ZoneOrVpnInterface::VpnInterface(_))
        ));
    }

    #[test]
    fn node_network_by_name_missing() {
        let f = Fixture::load();
        assert!(f.home.network_by_name(&id("nonexistent")).is_none());
    }

    // --- Client helper ---

    #[test]
    fn client_network_by_name_hit() {
        let f = Fixture::load();
        let ip = f
            .zone_only
            .network_by_name(&id("Home"), &id("lan"))
            .unwrap();
        assert_eq!(ip.to_string(), "192.168.1.60");
    }

    #[test]
    fn client_network_by_name_miss() {
        let f = Fixture::load();
        // Nowhere has no ips entry at all
        assert!(f.nowhere.network_by_name(&id("Home"), &id("lan")).is_none());
    }
}
