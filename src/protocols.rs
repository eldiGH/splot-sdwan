use std::fmt;

use serde::Deserialize;

#[derive(Deserialize, Hash, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocols {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}
