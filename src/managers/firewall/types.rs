use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::types::{ip::Ipv4Network, zone_ref::ZoneRef};

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

pub type TagResolution = HashMap<ZoneRef, HashSet<Ipv4Network>>;
