use std::{collections::BTreeSet, net::Ipv4Addr};

use log::{Level, debug, info, log_enabled};

use crate::{
    config::{Config, Node, NodeZoneDevice},
    managers::{NodeContext, UciManager, UciSection, UciSectionBuilder, naming},
    types::{identifier::Identifier, mac::MacAddress},
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "dhcp";

pub struct DhcpManager;

struct DhcpStaticLease {
    name: String,
    macs: BTreeSet<MacAddress>,
    ip: Ipv4Addr,
}

impl UciSection for DhcpStaticLease {
    const FILE: &'static str = FILE_NAME;

    fn section_type(&self) -> &str {
        "host"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.name.as_str()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed(&self.name))
            .set("ip", self.ip.to_string())
            .extend_list("mac", &self.macs)
    }
}

fn zone_device_to_lease(device_name: &Identifier, device: &NodeZoneDevice) -> DhcpStaticLease {
    DhcpStaticLease {
        ip: device.ip,
        macs: device.macs.clone().into(),
        name: device_name.to_string(),
    }
}

fn get_static_leases(own_node: &Node) -> Vec<DhcpStaticLease> {
    let mut static_leases = Vec::new();

    static_leases.extend(own_node.zones.values().flat_map(|zone| {
        zone.devices
            .iter()
            .filter(|(_, device)| !device.macs.is_empty())
            .map(|(device_name, device)| zone_device_to_lease(device_name, device))
    }));

    static_leases
}

fn get_client_static_leases(config: &Config, node_context: &NodeContext) -> Vec<DhcpStaticLease> {
    config
        .clients
        .iter()
        .filter_map(|(client_name, client)| {
            if client.macs.is_empty() {
                return None;
            };
            let networks = client.ips.get(node_context.own_name)?;

            let leases = networks
                .iter()
                .filter(|(zone_name, _)| node_context.own_node.zones.contains_key(*zone_name))
                .map(|(_, ip)| DhcpStaticLease {
                    macs: client.macs.clone().into(),
                    ip: *ip,
                    name: client_name.to_string(),
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
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand> {
        info!(
            "Generating DHCP config for node '{}'",
            node_context.own_name
        );

        let mut static_leases = get_static_leases(node_context.own_node);
        static_leases.extend(get_client_static_leases(config, node_context));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        managers::UciManager, splot_config::SplotConfig, test_support::config, uci::UciBatchCommand,
    };

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
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
          macless:
            ip: 192.168.1.51
            macs: []
clients:
  Phone:
    macs: BB:CC:DD:EE:FF:00
    ips:
      Home:
        lan: 192.168.1.60
  MeshOnly:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.0.100
";

    fn has_cmd(cmds: &[UciBatchCommand], s: &str) -> bool {
        cmds.iter().any(|c| c.to_string().contains(s))
    }

    fn cmds() -> Vec<UciBatchCommand> {
        let cfg = config(FIXTURE);
        let own_name: Identifier = "Home".parse().unwrap();
        let splot_config = SplotConfig::for_tests("AAAA");

        DhcpManager.generate_commands(
            &cfg,
            &NodeContext {
                own_node: cfg.nodes.get(&own_name).unwrap(),
                own_name: &own_name,
                splot_config: &splot_config,
            },
        )
    }

    #[test]
    fn zone_device_with_macs_gets_lease() {
        let c = cmds();
        assert!(
            has_cmd(&c, "dhcp.spl_host_printer"),
            "printer section missing"
        );
        assert!(has_cmd(&c, "ip='192.168.1.50'"), "printer IP missing");
        assert!(has_cmd(&c, "aa:bb:cc:dd:ee:ff"), "printer MAC missing");
    }

    #[test]
    fn zone_device_without_macs_no_lease() {
        assert!(!has_cmd(&cmds(), "spl_host_macless"));
    }

    #[test]
    fn global_client_with_macs_and_zone_ip_gets_lease() {
        let c = cmds();
        assert!(has_cmd(&c, "dhcp.spl_host_Phone"), "Phone section missing");
        assert!(has_cmd(&c, "ip='192.168.1.60'"), "Phone IP missing");
    }

    #[test]
    fn global_client_no_zone_ip_no_lease() {
        assert!(!has_cmd(&cmds(), "spl_host_MeshOnly"));
    }
}
