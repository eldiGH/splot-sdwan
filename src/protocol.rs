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

#[cfg(test)]
mod tests {
    use super::*;

    fn protocols(protos: impl IntoIterator<Item = Protocol>) -> Protocols {
        Protocols(protos.into_iter().collect())
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
        assert_eq!(Protocol::Icmp.to_string(), "icmp");
    }

    #[test]
    fn protocols_empty_display() {
        let p = protocols([]);
        assert_eq!(p.to_string(), "<empty>");
    }

    #[test]
    fn protocols_single_display() {
        assert_eq!(protocols([Protocol::Tcp]).to_string(), "tcp");
        assert_eq!(protocols([Protocol::Udp]).to_string(), "udp");
    }

    #[test]
    fn protocols_multi_contains_all() {
        let p = protocols([Protocol::Tcp, Protocol::Udp]);
        let s = p.to_string();
        assert!(s.contains("tcp"), "missing tcp in {s}");
        assert!(s.contains("udp"), "missing udp in {s}");
    }

    #[test]
    fn protocols_from_one_or_many_unique() {
        let omu: OneOrManyUnique<Protocol> = serde_yml::from_str("- tcp\n- udp").unwrap();
        let p: Protocols = omu.into();
        assert!(p.contains(&Protocol::Tcp));
        assert!(p.contains(&Protocol::Udp));
    }

    #[test]
    fn protocols_from_hashset() {
        let set = HashSet::from([Protocol::Icmp]);
        let p: Protocols = set.into();
        assert_eq!(p.to_string(), "icmp");
    }

    #[test]
    fn protocols_iterate() {
        let p = protocols([Protocol::Tcp, Protocol::Udp]);
        let collected: HashSet<Protocol> = p.iter().copied().collect();
        assert!(collected.contains(&Protocol::Tcp));
        assert!(collected.contains(&Protocol::Udp));
    }
}
