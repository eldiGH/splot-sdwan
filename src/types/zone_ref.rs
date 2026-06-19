use std::fmt;

use crate::{consts, types::identifier::Identifier};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum ZoneRef {
    Mesh,
    Named(Identifier),
}

impl ZoneRef {
    fn as_str(&self) -> &str {
        match self {
            Self::Mesh => consts::MESH_INTERFACE_NAME,
            Self::Named(id) => id.as_ref(),
        }
    }
}

impl AsRef<str> for ZoneRef {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ZoneRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    #[test]
    fn mesh_renders_constant() {
        let z = ZoneRef::Mesh;
        assert_eq!(z.to_string(), consts::MESH_INTERFACE_NAME);
        assert_eq!(z.as_ref(), consts::MESH_INTERFACE_NAME);
    }

    #[test]
    fn named_renders_its_name() {
        let z = ZoneRef::Named(id("lan"));
        assert_eq!(z.to_string(), "lan");
        assert_eq!(z.as_ref(), "lan");
    }

    #[test]
    fn display_eq_as_ref() {
        for z in [ZoneRef::Mesh, ZoneRef::Named(id("guest"))] {
            assert_eq!(z.to_string(), z.as_ref());
        }
    }

    #[test]
    fn equality() {
        assert_eq!(ZoneRef::Mesh, ZoneRef::Mesh);
        assert_eq!(ZoneRef::Named(id("lan")), ZoneRef::Named(id("lan")));
        assert_ne!(ZoneRef::Mesh, ZoneRef::Named(id("lan")));
        assert_ne!(ZoneRef::Named(id("lan")), ZoneRef::Named(id("guest")));
    }
}
