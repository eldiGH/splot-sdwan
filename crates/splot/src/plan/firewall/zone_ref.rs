use std::fmt;

use crate::{consts, types::identifier::Identifier};

/// One of the node's firewall zones: splot's mesh zone, or one the operator
/// declares under the node's `zones`. Each backend names it its own way.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum ZoneRef {
    Mesh,
    Named(Identifier),
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
}
