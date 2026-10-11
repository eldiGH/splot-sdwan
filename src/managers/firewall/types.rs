use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::types::{allow_from_ref::AllowFromRef, ip::Ipv4Network, zone_ref::ZoneRef};

pub enum FirewallAction {
    Accept,
    Drop,
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "ACCEPT"),
            Self::Drop => write!(f, "DROP"),
        }
    }
}

pub type TagResolution = BTreeMap<ZoneRef, BTreeSet<Ipv4Network>>;

/// Every `allowFrom` reference resolved to its addresses, grouped by zone.
pub type TagMap = BTreeMap<AllowFromRef, TagResolution>;
