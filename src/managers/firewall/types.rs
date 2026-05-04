use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv4Addr,
};

use crate::types::ip::Ipv4Network;

pub enum FirewallAction {
    Accept,
    Reject,
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "ACCEPT"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum IpOrNetwork {
    Ip(Ipv4Addr),
    Network(Ipv4Network),
}

impl fmt::Display for IpOrNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Network(network) => network.fmt(f),
        }
    }
}

pub type TagResolution = HashMap<String, HashSet<IpOrNetwork>>;
