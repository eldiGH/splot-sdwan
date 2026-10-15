use std::{collections::BTreeSet, net::Ipv4Addr};

use log::{Level, debug, info, log_enabled};

use crate::{
    config::Config,
    managers::{NodeContext, UciManager, UciSection, UciSectionBuilder, naming},
    model::{Network, host::Place},
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

/// A lease for each address a host with MACs has on this node's zones: the
/// node's devices, and global clients on its zones.
fn get_static_leases(network: &Network, own_name: &Identifier) -> Vec<DhcpStaticLease> {
    network
        .hosts()
        .iter()
        .filter(|host| !host.macs().is_empty())
        .flat_map(|host| {
            host.addresses()
                .iter()
                .filter(|address| {
                    matches!(address.place(), Place::Zone { node, .. } if node == own_name)
                })
                .map(|address| DhcpStaticLease {
                    name: host.id().name().to_string(),
                    macs: host.macs().clone(),
                    ip: address.ip(),
                })
        })
        .collect()
}

impl UciManager for DhcpManager {
    fn config_file(&self) -> &'static str {
        FILE_NAME
    }

    fn generate_commands(
        &self,
        _config: &Config,
        network: &Network,
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand> {
        info!(
            "Generating DHCP config for node '{}'",
            node_context.own_name
        );

        let static_leases = get_static_leases(network, node_context.own_name);

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
        managers::UciManager, splot_config::SplotConfig, test_support::checked,
        uci::UciBatchCommand,
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
  Cabin:
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          nas:
            ip: 192.168.2.50
            macs: AA:BB:CC:DD:EE:01
clients:
  Phone:
    macs: BB:CC:DD:EE:FF:00
    ips:
      Home:
        lan: 192.168.1.60
      Cabin:
        lan: 192.168.2.60
  MeshOnly:
    publicKey: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=
    meshIp: 10.100.0.100
";

    fn has_cmd(cmds: &[UciBatchCommand], s: &str) -> bool {
        cmds.iter().any(|c| c.to_string().contains(s))
    }

    fn cmds() -> Vec<UciBatchCommand> {
        let (config, network) = checked(FIXTURE);
        let own_name: Identifier = "Home".parse().unwrap();
        let splot_config = SplotConfig::for_tests("AAAA");

        DhcpManager.generate_commands(
            &config,
            &network,
            &NodeContext {
                own_node: config.nodes.get(&own_name).unwrap(),
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

    #[test]
    fn leases_only_on_this_nodes_zones() {
        // Cabin's nas, and Phone's IP on Cabin, are Cabin's to lease.
        let c = cmds();
        assert!(!has_cmd(&c, "spl_host_nas"), "Cabin's device got a lease");
        assert!(has_cmd(&c, "ip='192.168.1.60'"), "Phone's Home IP missing");
        assert!(!has_cmd(&c, "ip='192.168.2.60'"), "Phone's Cabin IP leased");
    }
}
