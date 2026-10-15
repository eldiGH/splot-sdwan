use std::{collections::BTreeMap, fs::File, iter, net::Ipv4Addr, path::Path};

use serde::Deserialize;

use crate::{
    protocol::Protocol,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ServiceLoc,
            ZoneLoc,
        },
        identifier::{Identifier, NestedIdentifier},
        ip::{Ipv4Interface, Ipv4Network},
        mac::MacAddress,
        port::{Port, ServicePort},
        schema_helpers::OneOrManyUnique,
        wan_via_target::{WanViaTarget, WanViaTargets},
        wg_key::WgPublicKey,
        zone_ref::ZoneRef,
    },
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceWan {
    pub via: WanViaTargets,

    #[serde(default)]
    pub sources: OneOrManyUnique<Ipv4Network>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub port: ServicePort,
    pub proto: OneOrManyUnique<Protocol>,

    #[serde(default)]
    pub allow_from: OneOrManyUnique<AllowFromRef>,

    pub wan: Option<ServiceWan>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeZoneDevice {
    pub ip: Ipv4Addr,
    pub macs: OneOrManyUnique<MacAddress>,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: BTreeMap<Identifier, Service>,
}

/// A device that reaches the mesh through one node: a peer on that node's mesh
/// interface only.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeHubClient {
    pub public_key: WgPublicKey,
    pub ip: Ipv4Addr,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: BTreeMap<Identifier, Service>,
}

/// A node's hub: a network inside the mesh space for its hub clients. Every other
/// node routes the whole network through this node, even while it's empty.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeHub {
    pub network: Ipv4Network,

    #[serde(default)]
    pub clients: BTreeMap<Identifier, NodeHubClient>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeZone {
    pub address: Ipv4Interface,

    #[serde(default)]
    pub devices: BTreeMap<Identifier, NodeZoneDevice>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Node {
    pub public_key: WgPublicKey,
    pub endpoint: Ipv4Addr,
    pub listen_port: Port,
    pub mesh_ip: Ipv4Addr,

    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
    #[serde(default)]
    pub services: BTreeMap<Identifier, Service>,
    #[serde(default)]
    pub zones: BTreeMap<Identifier, NodeZone>,
    pub hub: Option<NodeHub>,

    pub wan_zone: Option<Identifier>,
}

impl Node {
    pub fn addresses(&self) -> impl Iterator<Item = Ipv4Interface> {
        self.zones.values().map(|zone| zone.address)
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Client {
    pub mesh_ip: Option<Ipv4Addr>,
    pub public_key: Option<WgPublicKey>,

    #[serde(default)]
    pub macs: OneOrManyUnique<MacAddress>,
    #[serde(default)]
    pub ips: BTreeMap<Identifier, BTreeMap<Identifier, Ipv4Addr>>,
    #[serde(default)]
    pub services: BTreeMap<Identifier, Service>,
    #[serde(default)]
    pub tags: OneOrManyUnique<Identifier>,
}

#[derive(Debug)]
pub enum WanResolveError {
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
    pub fn ip_in_zone(&self, node_name: &Identifier, zone_name: &Identifier) -> Option<Ipv4Addr> {
        self.ips.get(node_name)?.get(zone_name).copied()
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

        // A client is in at most one zone per node (validated).
        self.ips
            .get(node_name)
            .into_iter()
            .flatten()
            .find(|(zone_name, _)| node.zones.contains_key(*zone_name))
            .map(|(zone_name, ip)| WanResolution {
                dest_ip: *ip,
                dest_zone: ZoneRef::Named(zone_name.clone()),
            })
            .ok_or(WanResolveError::Unreachable)
    }

    fn resolve_wan_qualified(
        &self,
        node_name: &Identifier,
        local_name: &Identifier,
        node: &Node,
    ) -> Result<WanResolution, WanResolveError> {
        if !node.zones.contains_key(local_name) {
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
    pub nodes: BTreeMap<Identifier, Node>,

    #[serde(default)]
    pub clients: BTreeMap<Identifier, Client>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("can't read config file")]
    Io(#[from] std::io::Error),
    #[error("can't parse config file")]
    Parse(#[from] serde_norway::Error),
}

impl Config {
    pub fn parse_file(path: &Path) -> Result<Self, ConfigError> {
        log::info!("Loading config from '{}'", path.display());

        let file = File::open(path)?;
        let config: Self = serde_norway::from_reader(file)?;

        log::info!(
            "Config loaded: {} node(s), {} client(s), mesh network {}",
            config.nodes.len(),
            config.clients.len(),
            config.mesh_network,
        );

        Ok(config)
    }

    pub fn find_node_by_public_key(&self, pubkey: &str) -> Option<(&Identifier, &Node)> {
        self.nodes
            .iter()
            .find_map(|(name, node)| (node.public_key.as_str() == pubkey).then_some((name, node)))
    }

    pub fn services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.nodes_own_services()
            .chain(self.devices_services())
            .chain(self.hub_clients_services())
            .chain(self.clients_services())
    }

    fn nodes_own_services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.nodes.iter().flat_map(|(node_name, node)| {
            node.services.iter().map(|(service_name, service)| {
                (
                    service,
                    ServiceHost::Node {
                        node_name,
                        service_name,
                    },
                )
            })
        })
    }

    fn devices_services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.nodes.iter().flat_map(|(node_name, node)| {
            node.zones.iter().flat_map(|(zone_name, zone)| {
                zone.devices.iter().flat_map(|(device_name, device)| {
                    device.services.iter().map(|(service_name, service)| {
                        (
                            service,
                            ServiceHost::Device {
                                node_name,
                                zone_name,
                                device_name,
                                service_name,
                            },
                        )
                    })
                })
            })
        })
    }

    fn hub_clients_services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.nodes.iter().flat_map(|(node_name, node)| {
            node.hub.iter().flat_map(move |hub| {
                hub.clients.iter().flat_map(move |(client_name, client)| {
                    client.services.iter().map(move |(service_name, service)| {
                        (
                            service,
                            ServiceHost::HubClient {
                                node_name,
                                client_name,
                                service_name,
                            },
                        )
                    })
                })
            })
        })
    }

    fn clients_services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.clients.iter().flat_map(|(client_name, client)| {
            client.services.iter().map(|(service_name, service)| {
                (
                    service,
                    ServiceHost::Client {
                        client_name,
                        service_name,
                    },
                )
            })
        })
    }
}

#[derive(Clone, Copy)]
pub enum ServiceHost<'a> {
    Node {
        node_name: &'a Identifier,
        service_name: &'a Identifier,
    },
    Device {
        node_name: &'a Identifier,
        zone_name: &'a Identifier,
        device_name: &'a Identifier,
        service_name: &'a Identifier,
    },
    HubClient {
        node_name: &'a Identifier,
        client_name: &'a Identifier,
        service_name: &'a Identifier,
    },
    Client {
        client_name: &'a Identifier,
        service_name: &'a Identifier,
    },
}

impl ServiceHost<'_> {
    pub fn to_location(self, leaf: ServiceLoc) -> ConfigLocation {
        match self {
            Self::Node {
                node_name,
                service_name,
            } => ConfigLocation::Node(
                node_name.clone(),
                NodeLoc::Service(service_name.clone(), leaf),
            ),

            Self::Device {
                node_name,
                zone_name,
                device_name,
                service_name,
            } => ConfigLocation::Node(
                node_name.clone(),
                NodeLoc::Zone(
                    zone_name.clone(),
                    ZoneLoc::Device(
                        device_name.clone(),
                        DeviceLoc::Service(service_name.clone(), leaf),
                    ),
                ),
            ),

            Self::HubClient {
                node_name,
                client_name,
                service_name,
            } => ConfigLocation::Node(
                node_name.clone(),
                NodeLoc::Hub(HubLoc::Client(
                    client_name.clone(),
                    HubClientLoc::Service(service_name.clone(), leaf),
                )),
            ),

            Self::Client {
                client_name,
                service_name,
            } => ConfigLocation::Client(
                client_name.clone(),
                ClientLoc::Service(service_name.clone(), leaf),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;

    // One node with two zones. The clients cover every branch of resolve_wan and
    // its qualified variant.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
      iot:
        address: 192.168.3.1/24
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
        // ZoneOnly has no iot IP, but iot exists on Home
        let err = f
            .zone_only
            .resolve_wan_target(&qualified("Home", "iot"), &f.home)
            .unwrap_err();
        assert!(matches!(
            err,
            WanResolveError::QualifiedClientNotOnNetwork { network } if network == id("iot")
        ));
    }

    // --- Client helper ---

    #[test]
    fn client_ip_in_zone_hit() {
        let f = Fixture::load();
        let ip = f.zone_only.ip_in_zone(&id("Home"), &id("lan")).unwrap();
        assert_eq!(ip.to_string(), "192.168.1.60");
    }

    #[test]
    fn client_ip_in_zone_miss() {
        let f = Fixture::load();
        // Nowhere has no ips entry at all
        assert!(f.nowhere.ip_in_zone(&id("Home"), &id("lan")).is_none());
    }

    // --- Unknown keys are rejected at every level ---
    //
    // A typo below the top level used to be silently ignored. The worst case is a
    // misspelled `wan.sources`: the allowlist vanished and the service was exposed
    // to the whole internet, with `check` passing.

    fn parse_error(yaml: &str) -> String {
        match serde_norway::from_str::<Config>(yaml) {
            Ok(_) => panic!("config with an unknown key parsed successfully"),
            Err(err) => err.to_string(),
        }
    }

    const NODE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
";

    #[test]
    fn misspelled_wan_sources_is_rejected() {
        let err = parse_error(&format!(
            "{NODE}
    services:
      https:
        port: 443
        proto: tcp
        wan:
          via: Home
          source: 198.51.100.0/24
"
        ));
        assert!(err.contains("unknown field `source`"), "{err}");
    }

    #[test]
    fn misspelled_device_key_is_rejected() {
        let err = parse_error(&format!(
            "{NODE}
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.16
            macs: aa:bb:cc:00:00:02
            macss: aa:bb:cc:00:00:03
"
        ));
        assert!(err.contains("unknown field `macss`"), "{err}");
    }

    #[test]
    fn misspelled_hub_keys_are_rejected() {
        let err = parse_error(&format!(
            "{NODE}
    hub:
      network: 10.100.49.0/24
      client:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
"
        ));
        assert!(err.contains("unknown field `client`"), "{err}");

        let err = parse_error(&format!(
            "{NODE}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          tag: cameras
"
        ));
        assert!(err.contains("unknown field `tag`"), "{err}");
    }

    #[test]
    fn hub_client_services_are_services() {
        let cfg = config(&format!(
            "{NODE}
    hub:
      network: 10.100.49.0/24
      clients:
        camera:
          publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
          ip: 10.100.49.10
          services:
            rtsp:
              port: 554
              proto: tcp
              allowFrom: Home
"
        ));
        let locations: Vec<String> = cfg
            .services()
            .map(|(_, host)| host.to_location(ServiceLoc::Root).to_string())
            .collect();
        assert_eq!(locations, ["nodes.Home.hub.clients.camera.services.rtsp"]);
    }

    #[test]
    fn vpn_interfaces_are_rejected() {
        // Replaced by hubs (T18). A config written for the old shape must fail
        // loudly instead of silently dropping its VPN clients.
        let err = parse_error(&format!(
            "{NODE}
    vpnInterfaces:
      guests:
        listenPort: 51821
        address: 10.8.0.1/24
        clients: {{}}
"
        ));
        assert!(err.contains("unknown field `vpnInterfaces`"), "{err}");
    }

    #[test]
    fn misspelled_client_key_is_rejected() {
        let err = parse_error(&format!(
            "{NODE}
clients:
  Phone:
    meshIp: 10.100.0.100
    publicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
    tag: admin
"
        ));
        assert!(err.contains("unknown field `tag`"), "{err}");
    }
}
