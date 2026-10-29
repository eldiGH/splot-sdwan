use std::fmt;

use crate::{consts, model::host::Place, types::identifier::Identifier};

/// One of the node's firewall zones: splot's mesh zone, or one the operator
/// declares under the node's `zones`. Each backend names it its own way.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum ZoneRef {
    Mesh,
    Named(Identifier),
}

impl ZoneRef {
    /// The zone of `node` that what's at `place` is in: one of the node's own,
    /// else the mesh. Whatever isn't in one of its zones reaches it over
    /// WireGuard: its hub, other nodes' networks, the mesh itself.
    pub fn on(node: &Identifier, place: &Place) -> Self {
        place
            .zone_on(node)
            .map_or(Self::Mesh, |zone| Self::Named(zone.clone()))
    }
}

impl fmt::Display for ZoneRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mesh => f.write_str(consts::MESH_INTERFACE_NAME),
            Self::Named(id) => write!(f, "{id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    #[test]
    fn a_zone_reads_as_in_the_config() {
        assert_eq!(ZoneRef::Mesh.to_string(), "mesh");
        assert_eq!(ZoneRef::Named(id("lan")).to_string(), "lan");
    }

    #[test]
    fn equality() {
        assert_eq!(ZoneRef::Mesh, ZoneRef::Mesh);
        assert_eq!(ZoneRef::Named(id("lan")), ZoneRef::Named(id("lan")));
        assert_ne!(ZoneRef::Mesh, ZoneRef::Named(id("lan")));
        assert_ne!(ZoneRef::Named(id("lan")), ZoneRef::Named(id("guest")));
    }

    #[test]
    fn a_node_sees_its_own_zones_and_the_mesh_for_the_rest() {
        let home_lan = Place::Zone {
            node: id("Home"),
            zone: id("lan"),
        };
        assert_eq!(
            ZoneRef::on(&id("Home"), &home_lan),
            ZoneRef::Named(id("lan"))
        );
        // Cabin may have a lan of its own: Home's still arrives over the mesh.
        assert_eq!(ZoneRef::on(&id("Cabin"), &home_lan), ZoneRef::Mesh);
        // A hub is behind its node, but its clients are peers on the mesh.
        let home_hub = Place::Hub { node: id("Home") };
        assert_eq!(ZoneRef::on(&id("Home"), &home_hub), ZoneRef::Mesh);
        assert_eq!(ZoneRef::on(&id("Home"), &Place::Mesh), ZoneRef::Mesh);
    }
}
