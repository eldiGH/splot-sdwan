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
