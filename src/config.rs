use std::{collections::BTreeMap, fs::File, net::Ipv4Addr, path::Path};

use serde::Deserialize;

use crate::{
    protocol::Protocol,
    types::{
        allow_from_ref::AllowFromRef,
        config_location::{
            ClientLoc, ConfigLocation, DeviceLoc, HubClientLoc, HubLoc, NodeLoc, ServiceLoc,
            ZoneLoc,
        },
        identifier::Identifier,
        ip::{Ipv4Interface, Ipv4Network},
        mac::MacAddress,
        port::{Port, ServicePort},
        schema_helpers::OneOrManyUnique,
        wan_via_target::WanViaTargets,
        wg_key::WgPublicKey,
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
    /// The node's hub clients; none when it has no hub.
    pub fn hub_clients(&self) -> impl Iterator<Item = (&Identifier, &NodeHubClient)> {
        self.hub.iter().flat_map(|hub| &hub.clients)
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

impl Client {
    pub fn ip_in_zone(&self, node_name: &Identifier, zone_name: &Identifier) -> Option<Ipv4Addr> {
        self.ips.get(node_name)?.get(zone_name).copied()
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
            node.hub_clients().flat_map(move |(client_name, client)| {
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
    }

    fn clients_services<'a>(&'a self) -> impl Iterator<Item = (&'a Service, ServiceHost<'a>)> {
        self.clients.iter().flat_map(|(client_name, client)| {
            client.services.iter().map(|(service_name, service)| {
                (
                    service,
                    ServiceHost::Client {
                        client_name,
                        client,
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
        /// The client itself: unlike the other hosts, it has an address per node.
        client: &'a Client,
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
                ..
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

    // One client with an IP on Home's lan, one with none.
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes: {}
clients:
  ZoneOnly:
    ips:
      Home:
        lan: 192.168.1.60
  Nowhere: {}
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn client(name: &str) -> Client {
        config(FIXTURE).clients.remove(&id(name)).unwrap()
    }

    // --- Client helper ---

    #[test]
    fn client_ip_in_zone_hit() {
        let ip = client("ZoneOnly")
            .ip_in_zone(&id("Home"), &id("lan"))
            .unwrap();
        assert_eq!(ip.to_string(), "192.168.1.60");
    }

    #[test]
    fn client_ip_in_zone_miss() {
        // Nowhere has no ips entry at all
        assert!(
            client("Nowhere")
                .ip_in_zone(&id("Home"), &id("lan"))
                .is_none()
        );
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
