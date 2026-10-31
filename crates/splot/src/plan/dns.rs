//! The node's DNS: the names in its own domain, which it answers alone; the
//! other nodes' domains, forwarded to their DNS addresses over the mesh; and
//! the endpoint names inside a mesh domain, which always go to public DNS.

use std::{fmt, net::Ipv4Addr};

use crate::{
    model::{
        Network,
        host::{HostRef, Place},
        node::Node,
    },
    types::{dns::Hostname, identifier::Identifier},
};

#[derive(Debug)]
pub struct DnsPlan {
    /// The node's own domain, which it answers alone: what neither splot nor
    /// the operator's config has a name for there gets no answer from public
    /// DNS. None for a node without a domain.
    pub local: Option<Hostname>,
    pub records: Vec<Record>,
    pub aliases: Vec<Alias>,
    pub forwards: Vec<Forward>,
    /// Endpoint names inside a mesh domain: asked of public DNS, never through
    /// the mesh, which needs them to come up.
    pub public: Vec<Hostname>,
}

/// A host's name in the node's domain, and its address on the node.
#[derive(Debug)]
pub struct Record {
    pub host: HostRef,
    pub name: Hostname,
    pub ip: Ipv4Addr,
}

/// A name a service asks for: an alias of its host's name.
#[derive(Debug)]
pub struct Alias {
    pub host: HostRef,
    pub service: Identifier,
    pub name: Hostname,
    pub target: Hostname,
}

/// Another node's domain, and where that node answers it.
#[derive(Debug)]
pub struct Forward {
    pub node: Identifier,
    pub domain: Hostname,
    pub address: Ipv4Addr,
}

/// A host's own name in `domain`: checked to fit.
fn name_in(host: &HostRef, domain: &Hostname) -> Hostname {
    domain
        .with_label(host.name().as_ref())
        .expect("checked: a host with a record is named as a host, and fits its domain")
}

/// The names in `domain`, `own`'s: its devices, its hub clients and the global
/// clients on its zones (not the node itself), and the names their services
/// ask for (not a global client's).
fn names(network: &Network, own: &Node, domain: &Hostname) -> (Vec<Record>, Vec<Alias>) {
    let mut records = Vec::new();
    let mut aliases = Vec::new();

    for host in network.hosts() {
        if matches!(host.id(), HostRef::Node(_)) {
            continue;
        }
        let Some(address) = host
            .addresses()
            .iter()
            .find(|address| match address.place() {
                Place::Zone { node, .. } | Place::Hub { node } => node == own.name(),
                Place::Mesh => false,
            })
        else {
            continue;
        };

        let name = name_in(host.id(), domain);
        if !matches!(host.id(), HostRef::Client(_)) {
            for (service, offered) in network.services_of(host) {
                aliases.extend(offered.dns().iter().map(|label| {
                    Alias {
                        host: host.id().clone(),
                        service: service.clone(),
                        name: domain
                            .with_label(label.as_ref())
                            .expect("checked: a service's name fits its host's domain"),
                        target: name.clone(),
                    }
                }));
            }
        }
        records.push(Record {
            host: host.id().clone(),
            name,
            ip: address.ip(),
        });
    }

    (records, aliases)
}

pub(super) fn plan(network: &Network, own: &Node) -> DnsPlan {
    let domain = own.dns().map(|dns| dns.domain().clone());
    let (records, aliases) = domain
        .as_ref()
        .map(|domain| names(network, own, domain))
        .unwrap_or_default();

    let forwards = network
        .nodes()
        .filter(|node| node.name() != own.name())
        .filter_map(|node| {
            let dns = node.dns()?;
            Some(Forward {
                node: node.name().clone(),
                domain: dns.domain().clone(),
                address: dns.address(),
            })
        })
        .collect();

    let domains: Vec<&Hostname> = network
        .nodes()
        .filter_map(|node| node.dns().map(|dns| dns.domain()))
        .collect();
    let public = network
        .nodes()
        .filter_map(|node| node.endpoint()?.name())
        .filter(|name| domains.iter().any(|domain| name.is_within(domain)))
        .cloned()
        .collect();

    DnsPlan {
        local: domain,
        records,
        aliases,
        forwards,
        public,
    }
}

impl fmt::Display for DnsPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(domain) = &self.local {
            writeln!(f, "local {domain}")?;
        }
        for Record { host, name, ip } in &self.records {
            writeln!(f, "record {name}: {ip} ({host})")?;
        }
        for Alias {
            host,
            service,
            name,
            target,
        } in &self.aliases
        {
            writeln!(f, "alias {name} -> {target} ({host} {service})")?;
        }
        for Forward {
            node,
            domain,
            address,
        } in &self.forwards
        {
            writeln!(f, "forward {domain} to {address} ({node})")?;
        }
        for name in &self.public {
            writeln!(f, "public {name}")?;
        }

        Ok(())
    }
}
