use std::{collections::HashSet, net::Ipv4Addr};

use log::{Level, debug, info, log_enabled};

use crate::{
    config::{Config, NodeZoneDevice, ZoneOrVpnInterface},
    managers::{UciManager, UciSectionBuilder},
    naming,
    types::{identifier::Identifier, mac::MacAddress},
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "dhcp";

pub struct DhcpManager;

struct DhcpStaticLease {
    name: String,
    macs: HashSet<MacAddress>,
    ip: Ipv4Addr,
}

impl DhcpStaticLease {
    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FILE_NAME, &self.name, "host")
            .set("name", naming::name_prefixed(&self.name))
            .set("ip", self.ip.to_string())
            .extend_list("mac", self.macs.iter().map(|mac| mac.to_string()))
            .build()
    }
}

fn zone_device_to_lease(device_name: &Identifier, device: &NodeZoneDevice) -> DhcpStaticLease {
    DhcpStaticLease {
        ip: device.ip,
        macs: device.macs.clone().into(),
        name: device_name.to_string(),
    }
}

fn get_static_leases(config: &Config, own_name: &Identifier) -> Vec<DhcpStaticLease> {
    let mut static_leases = Vec::new();

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    static_leases.extend(node.zones.values().flat_map(|zone| {
        zone.devices
            .iter()
            .filter(|(_, device)| !device.macs.is_empty())
            .map(|(device_name, device)| zone_device_to_lease(device_name, device))
    }));

    static_leases
}

fn get_client_static_leases(config: &Config, own_name: &Identifier) -> Vec<DhcpStaticLease> {
    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    config
        .clients
        .iter()
        .filter_map(|(client_name, client)| {
            if client.macs.is_empty() {
                return None;
            };
            let networks = client.ips.get(own_name)?;

            let leases = networks.iter().filter_map(|(network_name, ip)| {
                match node.network_by_name(network_name)? {
                    ZoneOrVpnInterface::VpnInterface(_) => None,
                    ZoneOrVpnInterface::Zone(_) => Some(DhcpStaticLease {
                        macs: client.macs.clone().into(),
                        ip: *ip,
                        name: client_name.to_string(),
                    }),
                }
            });

            Some(leases.collect::<Vec<_>>())
        })
        .flatten()
        .collect()
}

impl UciManager for DhcpManager {
    fn config_file(&self) -> &'static str {
        FILE_NAME
    }

    fn generate_commands(
        &self,
        config: &crate::config::Config,
        own_name: &Identifier,
    ) -> Vec<UciBatchCommand> {
        info!("Generating DHCP config for node '{own_name}'");

        let mut static_leases = get_static_leases(config, own_name);
        static_leases.extend(get_client_static_leases(config, own_name));

        info!("  {} static lease(s)", static_leases.len());
        if log_enabled!(Level::Debug) {
            for lease in &static_leases {
                debug!(
                    "  Lease '{}': {} → {} MAC(s)",
                    lease.name,
                    lease.ip,
                    lease.macs.len()
                );
            }
        }

        static_leases
            .iter()
            .flat_map(|lease| lease.to_uci_commands())
            .collect()
    }
}
