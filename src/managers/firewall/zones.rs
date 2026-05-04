use crate::{
    config::Config,
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
            forward: FirewallAction::Reject,
            input: FirewallAction::Reject,
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

pub fn get_firewall_zones(config: &Config, own_name: &str) -> Vec<FirewallZone> {
    let mut zones = vec![FirewallZone {
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        network: vec![naming::mesh_interface()],

        ..Default::default()
    }];

    let node = config
        .nodes
        .get(own_name)
        .expect("own node not found — config should be validated before calling managers");

    zones.extend(node.vpn_interfaces.keys().map(|name| FirewallZone {
        name: name.clone(),
        network: vec![naming::interface(name)],
        ..Default::default()
    }));

    zones
}
