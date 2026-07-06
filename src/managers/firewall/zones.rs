use crate::{
    config::Node,
    consts,
    managers::{
        UciSectionBuilder,
        firewall::{consts::FIREWALL_FILE_NAME, types::FirewallAction},
    },
    naming,
    uci::UciBatchCommand,
};

pub struct FirewallZone {
    pub name: String,
    pub network: Vec<String>,
    pub input: FirewallAction,
    pub output: FirewallAction,
    pub forward: FirewallAction,
}

impl Default for FirewallZone {
    fn default() -> Self {
        Self {
            forward: FirewallAction::Drop,
            input: FirewallAction::Drop,
            output: FirewallAction::Accept,
            name: String::new(),
            network: Vec::new(),
        }
    }
}

impl FirewallZone {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "zone")
            .set("name", naming::name_prefixed(&self.name))
            .set("input", self.input.to_string())
            .set("output", self.output.to_string())
            .set("forward", self.forward.to_string())
            .extend_list("network", &self.network)
            .build()
    }
}

pub fn get_firewall_zones(own_node: &Node) -> Vec<FirewallZone> {
    let mut zones = vec![FirewallZone {
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        network: vec![naming::mesh_interface()],

        ..Default::default()
    }];

    zones.extend(own_node.vpn_interfaces.keys().map(|name| FirewallZone {
        name: name.to_string(),
        network: vec![naming::interface(name)],
        ..Default::default()
    }));

    zones
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;

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
";

    fn zones() -> Vec<FirewallZone> {
        let cfg = config(FIXTURE);
        let own_name: crate::types::identifier::Identifier = "Home".parse().unwrap();
        get_firewall_zones(cfg.nodes.get(&own_name).unwrap())
    }

    #[test]
    fn mesh_zone_always_present() {
        assert!(zones().iter().any(|z| z.name == "mesh"));
    }

    #[test]
    fn mesh_zone_network_is_spl_mesh() {
        let z = zones();
        let mesh = z.iter().find(|z| z.name == "mesh").unwrap();
        assert_eq!(mesh.network, vec!["spl_mesh"]);
    }

    #[test]
    fn vpn_interface_produces_zone() {
        assert!(zones().iter().any(|z| z.name == "vpn_a"));
    }

    #[test]
    fn vpn_zone_network_is_spl_interface_name() {
        let z = zones();
        let vpn = z.iter().find(|z| z.name == "vpn_a").unwrap();
        assert_eq!(vpn.network, vec!["spl_vpn_a"]);
    }

    #[test]
    fn default_policy_drop_in_drop_fwd_accept_out() {
        // Zero-trust default: drop unsolicited input and transit, allow the router's
        // own egress. Access is granted only via explicit service rules.
        for zone in zones() {
            assert!(matches!(zone.input, FirewallAction::Drop));
            assert!(matches!(zone.forward, FirewallAction::Drop));
            assert!(matches!(zone.output, FirewallAction::Accept));
        }
    }

    #[test]
    fn operator_managed_zones_not_included() {
        // "lan" is operator-managed; splot must not create a firewall zone for it.
        assert!(!zones().iter().any(|z| z.name == "lan"));
    }
}
