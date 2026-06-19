use std::{
    collections::{HashSet, hash_set},
    fmt,
    str::FromStr,
};

use serde::Deserialize;

use crate::types::{
    identifier::{Identifier, NestedIdentifier, ParseIdentifierError, ParseNestedIdentifierError},
    schema_helpers::OneOrManyUnique,
};

#[derive(Debug)]
pub enum ParseWanViaTargetError {
    InvalidIdentifier(ParseIdentifierError),
    InvalidNested(ParseNestedIdentifierError),
}

impl fmt::Display for ParseWanViaTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(e) => write!(f, "invalid wan target: {e}"),
            Self::InvalidNested(e) => write!(f, "invalid qualified wan target: {e}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize)]
#[serde(try_from = "String")]
pub enum WanViaTarget {
    Bare(Identifier),
    Qualified(NestedIdentifier),
}

impl FromStr for WanViaTarget {
    type Err = ParseWanViaTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('.') {
            return s
                .parse::<NestedIdentifier>()
                .map(Self::Qualified)
                .map_err(ParseWanViaTargetError::InvalidNested);
        }

        s.parse::<Identifier>()
            .map(Self::Bare)
            .map_err(ParseWanViaTargetError::InvalidIdentifier)
    }
}

impl TryFrom<String> for WanViaTarget {
    type Error = ParseWanViaTargetError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for WanViaTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bare(id) => id.fmt(f),
            Self::Qualified(nested) => nested.fmt(f),
        }
    }
}

impl WanViaTarget {
    pub fn node(&self) -> &Identifier {
        match self {
            Self::Bare(node) => node,
            Self::Qualified(nested_identifier) => &nested_identifier.node,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "OneOrManyUnique<WanViaTarget>")]
pub struct WanViaTargets(OneOrManyUnique<WanViaTarget>);

#[derive(Debug)]
pub enum ParseWanViaTargetsError {
    DuplicateNode { node: Identifier },
}

impl fmt::Display for ParseWanViaTargetsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode { node } => write!(
                f,
                "node '{node}' appears more than once — each node should appear at most once in wan.via"
            ),
        }
    }
}

impl TryFrom<OneOrManyUnique<WanViaTarget>> for WanViaTargets {
    type Error = ParseWanViaTargetsError;

    fn try_from(value: OneOrManyUnique<WanViaTarget>) -> Result<Self, Self::Error> {
        let mut seen: HashSet<&Identifier> = HashSet::new();

        for via in &value {
            let node = via.node();
            if !seen.insert(node) {
                return Err(ParseWanViaTargetsError::DuplicateNode { node: node.clone() });
            }
        }

        Ok(Self(value))
    }
}

impl<'a> IntoIterator for &'a WanViaTargets {
    type Item = &'a WanViaTarget;
    type IntoIter = hash_set::Iter<'a, WanViaTarget>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl WanViaTargets {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> hash_set::Iter<'_, WanViaTarget> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(s: &str) -> WanViaTarget {
        s.parse().unwrap()
    }

    #[test]
    fn target_bare_and_qualified() {
        let bare = target("Home");
        assert!(matches!(bare, WanViaTarget::Bare(_)));
        assert_eq!(bare.node().as_ref(), "Home");

        let qualified = target("Home.lan");
        assert!(matches!(qualified, WanViaTarget::Qualified(_)));
        // node() reaches through the qualified form to the node segment
        assert_eq!(qualified.node().as_ref(), "Home");
    }

    #[test]
    fn target_parse_errors() {
        assert!(matches!(
            "".parse::<WanViaTarget>(),
            Err(ParseWanViaTargetError::InvalidIdentifier(_))
        ));
        assert!(matches!(
            "a.b.c".parse::<WanViaTarget>(),
            Err(ParseWanViaTargetError::InvalidNested(_))
        ));
    }

    #[test]
    fn targets_distinct_nodes_ok() {
        let set = OneOrManyUnique(HashSet::from([target("Home"), target("Cabin")]));
        let targets = WanViaTargets::try_from(set).unwrap();
        assert_eq!(targets.iter().count(), 2);
        assert!(!targets.is_empty());
    }

    #[test]
    fn targets_duplicate_node_rejected() {
        // bare and qualified forms that name the same node are a duplicate
        let set = OneOrManyUnique(HashSet::from([target("Home"), target("Home.lan")]));
        let err = WanViaTargets::try_from(set).unwrap_err();
        assert!(matches!(
            err,
            ParseWanViaTargetsError::DuplicateNode { node } if node.as_ref() == "Home"
        ));
    }

    #[test]
    fn targets_single() {
        let set = OneOrManyUnique(HashSet::from([target("Home")]));
        let targets = WanViaTargets::try_from(set).unwrap();
        assert_eq!(targets.iter().count(), 1);
    }
}
