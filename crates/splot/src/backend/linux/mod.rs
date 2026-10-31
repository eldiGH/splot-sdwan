//! Linux: the plan as the files of the programs a Linux node runs: its
//! WireGuard with wg-quick, its firewall with nftables, its DHCP with dnsmasq.

mod dnsmasq;
mod nftables;
mod wg_quick;

use log::info;
use splot_core::protocol::linux::Rendered;

use crate::{model::platform::Platform, plan::NodePlan};

/// The plan as the files a Linux node holds, with placeholders where its
/// secrets go; its zones on the interfaces `platform` says.
pub fn render(plan: &NodePlan, platform: &Platform) -> Rendered {
    info!("Rendering the Linux config of node '{}'", plan.node);

    Rendered {
        node: plan.node.clone(),
        public_key: plan.public_key.clone(),
        wireguard: plan
            .wireguard
            .as_ref()
            .map(|wireguard| wg_quick::render(&plan.node, wireguard)),
        firewall: plan
            .firewall
            .as_ref()
            .map(|firewall| nftables::render(&plan.node, firewall, platform)),
        dhcp: plan
            .dhcp
            .as_ref()
            .map(|dhcp| dnsmasq::render(&plan.node, dhcp, platform)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support, types::platform::Os};

    #[test]
    fn example_config_snapshot() {
        // The wg-quick file splot renders for every Linux node of the example,
        // with its secrets as placeholders: what the dry run shows. Then its
        // nft file, and its dnsmasq file.
        let network = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../splot.example.yml"
        )));
        let mut rendered = 0;

        for node in network
            .nodes()
            .filter(|node| node.platform().os() == Os::Linux)
        {
            let plan = plan::plan(&network, node.name()).unwrap();
            let rendered_node = render(&plan, node.platform());
            let config = rendered_node.wireguard.unwrap();

            insta::assert_snapshot!(format!("example_{}", node.name()), config.masked());
            insta::assert_snapshot!(
                format!("example_{}_nftables", node.name()),
                rendered_node.firewall.unwrap()
            );
            insta::assert_snapshot!(
                format!("example_{}_dnsmasq", node.name()),
                rendered_node.dhcp.unwrap()
            );
            rendered += 1;
        }
        assert!(rendered > 0);
    }

    #[test]
    fn a_node_whose_wireguard_splot_leaves_alone_has_no_file() {
        let network = test_support::checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: linux
      wireguard: none
      firewall: none
      dhcp: none
      dns: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        let home = network.node(&"Home".parse().unwrap()).unwrap();
        let plan = plan::plan(&network, home.name()).unwrap();
        let rendered = render(&plan, home.platform());

        assert!(rendered.wireguard.is_none());
        assert!(rendered.firewall.is_none());
        assert_eq!(rendered.public_key, plan.public_key);
    }
}
