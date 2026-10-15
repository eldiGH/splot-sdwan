use crate::{
    consts,
    managers::{
        UciSection, UciSectionBuilder,
        firewall::{consts::FIREWALL_FILE_NAME, types::FirewallAction},
        naming,
    },
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

impl UciSection for FirewallZone {
    const FILE: &'static str = FIREWALL_FILE_NAME;

    fn section_type(&self) -> &str {
        "zone"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [self.name.as_str()]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        section
            .set("name", naming::name_prefixed(&self.name))
            .set("input", self.input.to_string())
            .set("output", self.output.to_string())
            .set("forward", self.forward.to_string())
            .extend_list("network", &self.network)
    }
}

/// splot's zones: the mesh is the only one. The operator's zones (`lan`, …)
/// aren't splot's to create.
pub fn get_firewall_zones() -> Vec<FirewallZone> {
    vec![FirewallZone {
        name: consts::MESH_INTERFACE_NAME.to_owned(),
        network: vec![naming::mesh_interface().to_string()],

        ..Default::default()
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_is_the_only_zone() {
        let names: Vec<String> = get_firewall_zones().into_iter().map(|z| z.name).collect();
        assert_eq!(names, ["mesh"]);
    }

    #[test]
    fn mesh_zone_network_is_spl_mesh() {
        let z = get_firewall_zones();
        let mesh = z.iter().find(|z| z.name == "mesh").unwrap();
        assert_eq!(mesh.network, vec!["spl_mesh"]);
    }

    #[test]
    fn default_policy_drop_in_drop_fwd_accept_out() {
        // Zero-trust default: drop unsolicited input and transit, allow the router's
        // own egress. Access is granted only via explicit service rules.
        for zone in get_firewall_zones() {
            assert!(matches!(zone.input, FirewallAction::Drop));
            assert!(matches!(zone.forward, FirewallAction::Drop));
            assert!(matches!(zone.output, FirewallAction::Accept));
        }
    }
}
