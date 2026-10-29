//! Services, and who their `allowFrom` lets in.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    model::host::{HostAddress, Place},
    types::{identifier::Identifier, ip::Ipv4Network, port::ServicePort, protocol::Protocol},
};

/// A service a host offers.
#[derive(Debug)]
pub struct Service {
    pub(super) port: ServicePort,
    pub(super) proto: BTreeSet<Protocol>,
    pub(super) sources: Sources,
    pub(super) wan: Option<Wan>,
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

    /// How it's exposed to the internet, if it is.
    pub fn wan(&self) -> Option<&Wan> {
        self.wan.as_ref()
    }
}

/// How a service is exposed to the internet.
#[derive(Debug)]
pub struct Wan {
    /// What each node it's exposed through forwards it to: one of its host's
    /// addresses.
    pub(super) targets: BTreeMap<Identifier, HostAddress>,
    /// The CIDRs the internet side may come from; none means anyone.
    pub(super) sources: BTreeSet<Ipv4Network>,
}

impl Wan {
    /// What `node` forwards the service to, if it's exposed through it.
    pub fn target(&self, node: &Identifier) -> Option<&HostAddress> {
        self.targets.get(node)
    }

    pub fn sources(&self) -> &BTreeSet<Ipv4Network> {
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

    pub fn place(&self) -> &Place {
        &self.place
    }
}

/// What a service's `allowFrom` lets in, resolved. A source two references name
/// is in it once.
#[derive(Debug, Default)]
pub struct Sources {
    /// What its references name but nodes themselves: the same on every node.
    pub(super) everywhere: BTreeSet<Source>,
    /// The nodes it names themselves (`{Node}.$node`), each with its own
    /// addresses: its mesh IP and its address on each of its zones.
    pub(super) nodes: BTreeMap<Identifier, BTreeSet<Source>>,
}

impl Sources {
    /// The sources `node` lets in: all but its own addresses, since what the
    /// node itself sends leaves through its output. `$node`, the node the rule
    /// is on, names only those, so it adds nothing on any node.
    pub fn on<'a>(&'a self, node: &'a Identifier) -> impl Iterator<Item = &'a Source> {
        let others = self
            .nodes
            .iter()
            .filter(move |(name, _)| *name != node)
            .flat_map(|(_, sources)| sources);
        self.everywhere.iter().chain(others)
    }

    /// Whether it lets in nothing, on any node.
    pub fn is_empty(&self) -> bool {
        self.everywhere.is_empty() && self.nodes.values().all(BTreeSet::is_empty)
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
    fn a_node_lets_in_every_node_named_but_itself() {
        let sources = Sources {
            everywhere: BTreeSet::from([source("192.168.3.0/24", "Cabin")]),
            nodes: BTreeMap::from([
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
        assert_eq!(on(&sources, "Home"), ["192.168.3.0/24", "192.168.3.1/32"]);
        assert_eq!(on(&sources, "Cabin"), ["192.168.3.0/24", "192.168.1.1/32"]);
        // A node it doesn't name lets in every one it does, by name.
        assert_eq!(
            on(&sources, "Attic"),
            ["192.168.3.0/24", "192.168.3.1/32", "192.168.1.1/32"]
        );
    }
}
