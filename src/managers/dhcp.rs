use std::{collections::HashSet, net::Ipv4Addr};

use log::{debug, info, log_enabled, Level};

use crate::{
    config::{Config, NodeLanDevice},
    managers::{UciManager, UciSectionBuilder},
    naming,
    types::mac::MacAddress,
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

fn lan_device_to_lease(device_name: &str, device: &NodeLanDevice) -> DhcpStaticLease {
    DhcpStaticLease {
        ip: device.ip,
        macs: device
            .macs
            .as_ref()
            .expect("devices without macs should already be filtered out")
            .clone()
            .into(),
        name: device_name.to_owned(),
    }
}

fn get_static_leases(config: &Config, own_name: &str) -> Vec<DhcpStaticLease> {
    let mut static_leases = Vec::new();

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    static_leases.extend(
        node.lan
            .devices
            .iter()
            .flatten()
            .filter(|(_, device)| device.macs.as_ref().is_some_and(|macs| !macs.is_empty()))
            .map(|(device_name, device)| lan_device_to_lease(device_name, device)),
    );

    static_leases
}

impl UciManager for DhcpManager {
    fn config_file(&self) -> &'static str {
        FILE_NAME
    }

    fn generate_commands(
        &self,
        config: &crate::config::Config,
        own_name: &str,
    ) -> Vec<UciBatchCommand> {
        info!("Generating DHCP config for node '{own_name}'");

        let static_leases = get_static_leases(config, own_name);

        info!("  {} static lease(s)", static_leases.len());
        if log_enabled!(Level::Debug) {
            for lease in &static_leases {
                debug!("  Lease '{}': {} → {} MAC(s)", lease.name, lease.ip, lease.macs.len());
            }
        }

        static_leases
            .iter()
            .flat_map(|lease| lease.to_uci_commands())
            .collect()
    }
}
