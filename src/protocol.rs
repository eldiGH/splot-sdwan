use std::{collections::HashSet, fmt, ops::Deref};

use serde::Deserialize;

use crate::types::schema_helpers::OneOrManyUnique;

#[derive(Deserialize, Hash, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

pub struct Protocols(HashSet<Protocol>);

impl Deref for Protocols {
    type Target = HashSet<Protocol>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.iter();
        let Some(first_item) = iter.next() else {
            return write!(f, "<empty>");
        };

        write!(f, "{first_item}")?;

        for proto in iter {
            write!(f, ", {proto}")?;
        }

        Ok(())
    }
}

impl From<HashSet<Protocol>> for Protocols {
    fn from(value: HashSet<Protocol>) -> Self {
        Self(value)
    }
}

impl<'a> IntoIterator for &'a Protocols {
    type Item = &'a Protocol;
    type IntoIter = std::collections::hash_set::Iter<'a, Protocol>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<OneOrManyUnique<Protocol>> for Protocols {
    fn from(value: OneOrManyUnique<Protocol>) -> Self {
        Self(value.0)
    }
}
