use log::{Level, debug, info, log_enabled};

use crate::{
    managers::{UciManager, UciSection, UciSectionBuilder, naming},
    plan::{NodePlan, dhcp::Lease},
    splot_config::SplotConfig,
    uci::UciBatchCommand,
};

const FILE_NAME: &str = "dhcp";

pub struct DhcpManager;

impl UciSection for Lease {
    const FILE: &'static str = FILE_NAME;

    fn section_type(&self) -> &str {
        "host"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.host.name().as_ref()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed(self.host.name().as_ref()))
            .set("ip", self.ip.to_string())
            .extend_list("mac", &self.macs)
    }
}

impl UciManager for DhcpManager {
    fn config_file(&self) -> &'static str {
        FILE_NAME
    }

    fn generate_commands(
        &self,
        plan: &NodePlan,
        _splot_config: &SplotConfig,
    ) -> Vec<UciBatchCommand> {
        let leases = &plan.dhcp.leases;

        info!("Generating DHCP config for node '{}'", plan.node);
        info!("  {} static lease(s)", leases.len());
        if log_enabled!(Level::Debug) {
            for lease in leases {
                debug!(
                    "  Lease '{}': {} → {} MAC(s)",
                    lease.host,
                    lease.ip,
                    lease.macs.len()
                );
            }
        }

        leases
            .iter()
            .flat_map(|lease| lease.to_uci_commands())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support::checked};

    #[test]
    fn a_lease_is_a_host_section_named_after_the_host() {
        let network = checked(
            "
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
          printer: { ip: 192.168.1.50, macs: [AA:BB:CC:DD:EE:FF, AA:BB:CC:DD:EE:01] }
",
        );
        let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
        let commands: Vec<String> = DhcpManager
            .generate_commands(&plan, &SplotConfig::for_tests("AAAA"))
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            commands,
            [
                "set dhcp.spl_host_printer='host'",
                "set dhcp.spl_host_printer.name='[SPLOT] printer'",
                "set dhcp.spl_host_printer.ip='192.168.1.50'",
                "add_list dhcp.spl_host_printer.mac='aa:bb:cc:dd:ee:01'",
                "add_list dhcp.spl_host_printer.mac='aa:bb:cc:dd:ee:ff'",
            ]
        );
    }
}
