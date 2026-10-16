//! Services, and who their `allowFrom` lets in.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    model::host::Place,
    protocol::Protocol,
    types::{identifier::Identifier, ip::Ipv4Network, port::ServicePort},
};

/// A service a host offers.
#[derive(Debug)]
pub struct Service {
    pub(super) port: ServicePort,
    pub(super) proto: BTreeSet<Protocol>,
    pub(super) sources: Sources,
}

impl Service {
    pub fn port(&self) -> ServicePort {
        self.port
    }

    pub fn proto(&self) -> &BTreeSet<Protocol> {
        &self.proto
    }

    /// Who its `allowFrom` lets in.
    pub fn sources(&self) -> &Sources {
        &self.sources
    }
}

/// A network an `allowFrom` lets in, and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub(super) network: Ipv4Network,
    pub(super) place: Place,
}

impl Source {
    pub fn network(&self) -> Ipv4Network {
        self.network
    }
}

/// What a service's `allowFrom` lets in, resolved. A source two references name
/// is in it once.
#[derive(Debug, Default)]
pub struct Sources {
    /// What its references name: the same on every node.
    pub(super) everywhere: BTreeSet<Source>,
    /// What `$node` names on each node: the node's own address on each of its
    /// zones. Empty when `allowFrom` has no `$node`.
    pub(super) this_node: BTreeMap<Identifier, BTreeSet<Source>>,
}

impl Sources {
    /// The sources on `node`, where `$node` is that node.
    pub fn on(&self, node: &Identifier) -> impl Iterator<Item = &Source> {
        self.everywhere
            .iter()
            .chain(self.this_node.get(node).into_iter().flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn source(network: &str, node: &str) -> Source {
        Source {
            network: network.parse().unwrap(),
            place: Place::Zone {
                node: id(node),
                zone: id("lan"),
            },
        }
    }

    fn on(sources: &Sources, node: &str) -> Vec<String> {
        sources
            .on(&id(node))
            .map(|source| source.network().to_string())
            .collect()
    }

    #[test]
    fn this_node_is_the_node_asked_about() {
        let sources = Sources {
            everywhere: BTreeSet::from([source("192.168.3.0/24", "Cabin")]),
            this_node: BTreeMap::from([
                (
                    id("Home"),
                    BTreeSet::from([source("192.168.1.1/32", "Home")]),
                ),
                (
                    id("Cabin"),
                    BTreeSet::from([source("192.168.3.1/32", "Cabin")]),
                ),
            ]),
        };
        assert_eq!(on(&sources, "Home"), ["192.168.3.0/24", "192.168.1.1/32"]);
        assert_eq!(on(&sources, "Cabin"), ["192.168.3.0/24", "192.168.3.1/32"]);
        // A node that isn't in the table has no addresses of its own to add.
        assert_eq!(on(&sources, "Attic"), ["192.168.3.0/24"]);
    }
}
