use crate::{
    backend::openwrt::{
        firewall::target,
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    consts,
    plan::firewall::ZonePolicy,
};

/// The mesh zone, splot's one zone: the operator's zones (`lan`, …) aren't
/// splot's to create.
pub(super) struct MeshZone<'a>(pub &'a ZonePolicy);

impl UciSection for MeshZone<'_> {
    fn section_type(&self) -> &str {
        "zone"
    }

    fn id(&self) -> impl IntoIterator<Item = &str> {
        [consts::MESH_INTERFACE_NAME]
    }

    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let ZonePolicy {
            input,
            output,
            forward,
        } = *self.0;

        section
            .set("name", naming::name_prefixed(consts::MESH_INTERFACE_NAME))
            .set("input", target(input))
            .set("output", target(output))
            .set("forward", target(forward))
            .extend_list("network", [naming::mesh_interface()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::firewall::Verdict;

    #[test]
    fn the_mesh_zone_covers_the_mesh_interface_with_the_plans_policy() {
        let policy = ZonePolicy {
            input: Verdict::Drop,
            output: Verdict::Accept,
            forward: Verdict::Drop,
        };
        let commands: Vec<String> = MeshZone(&policy)
            .to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            commands,
            [
                "set firewall.spl_zone_mesh='zone'",
                "set firewall.spl_zone_mesh.name='[SPLOT] mesh'",
                "set firewall.spl_zone_mesh.input='DROP'",
                "set firewall.spl_zone_mesh.output='ACCEPT'",
                "set firewall.spl_zone_mesh.forward='DROP'",
                "add_list firewall.spl_zone_mesh.network='spl_mesh'",
            ]
        );
    }
}
