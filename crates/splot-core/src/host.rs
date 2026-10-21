//! Which host it is: what splot and its agent both name a host by.

use std::fmt;

use crate::identifier::Identifier;

/// Which host it is, by the name an `allowFrom` refers to it with. A zone device
/// and a hub client share their node's namespace (`Cabin.camera` either way), so
/// both are `Local`; which of the two it is shows in where its address lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostRef {
    Node(Identifier),
    Local { node: Identifier, name: Identifier },
    Client(Identifier),
}

/// Config notation: `Home`, `Cabin.camera`, `Laptop`, as an `allowFrom` names it.
impl fmt::Display for HostRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(name) | Self::Client(name) => write!(f, "{name}"),
            Self::Local { node, name } => write!(f, "{node}.{name}"),
        }
    }
}

impl HostRef {
    /// Its own name, without its node's.
    pub fn name(&self) -> &Identifier {
        match self {
            Self::Node(name) | Self::Local { name, .. } | Self::Client(name) => name,
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
    fn a_host_ref_reads_as_in_the_config() {
        assert_eq!(HostRef::Node(id("Home")).to_string(), "Home");
        assert_eq!(HostRef::Client(id("Laptop")).to_string(), "Laptop");
        let camera = HostRef::Local {
            node: id("Cabin"),
            name: id("camera"),
        };
        assert_eq!(camera.to_string(), "Cabin.camera");
    }
}
