use std::fmt;

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
