use std::{fmt, str::FromStr};

use serde::Deserialize;

use crate::{
    consts,
    types::identifier::{
        Identifier, NestedIdentifier, ParseIdentifierError, ParseNestedIdentifierError,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ParseAllowFromRefError {
    #[error("invalid allowFrom reference: {0}")]
    InvalidIdentifier(ParseIdentifierError),
    #[error("invalid qualified allowFrom reference: {0}")]
    InvalidNested(ParseNestedIdentifierError),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum AllowFromRef {
    Bare(Identifier),
    Nested(NestedIdentifier),
    /// `$node`: the node the rule is on.
    SelfNode,
    /// `{Node}.$node`: that node itself, named from anywhere.
    NodeItself(Identifier),
    /// `{Node}.$hub`: that node's hub network.
    Hub(Identifier),
}

impl FromStr for AllowFromRef {
    type Err = ParseAllowFromRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == consts::CURRENT_NODE_IDENTIFIER {
            return Ok(Self::SelfNode);
        }

        // A keyword of splot's, qualified by a node.
        let of_node = |node: &str, reference: fn(Identifier) -> Self| {
            node.parse().map(reference).map_err(|error| {
                ParseAllowFromRefError::InvalidNested(ParseNestedIdentifierError::InvalidNode(
                    error,
                ))
            })
        };
        match s.split_once('.') {
            Some((node, consts::CURRENT_NODE_IDENTIFIER)) => {
                return of_node(node, Self::NodeItself);
            }
            Some((node, consts::HUB_IDENTIFIER)) => return of_node(node, Self::Hub),
            _ => {}
        }

        if s.contains('.') {
            return s
                .parse::<NestedIdentifier>()
                .map(Self::Nested)
                .map_err(ParseAllowFromRefError::InvalidNested);
        }

        s.parse::<Identifier>()
            .map(Self::Bare)
            .map_err(ParseAllowFromRefError::InvalidIdentifier)
    }
}

impl TryFrom<String> for AllowFromRef {
    type Error = ParseAllowFromRefError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for AllowFromRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bare(id) => id.fmt(f),
            Self::Nested(nested) => nested.fmt(f),
            Self::SelfNode => write!(f, "$node"),
            Self::NodeItself(node) => write!(f, "{node}.$node"),
            Self::Hub(node) => write!(f, "{node}.$hub"),
        }
    }
}

impl AllowFromRef {
    pub fn nested(node: Identifier, local: Identifier) -> Self {
        Self::Nested(NestedIdentifier { node, local })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<AllowFromRef, ParseAllowFromRefError> {
        s.parse()
    }

    #[test]
    fn self_node_sentinel() {
        let r = parse("$node").unwrap();
        assert_eq!(r, AllowFromRef::SelfNode);
        assert_eq!(r.to_string(), "$node");
    }

    #[test]
    fn a_node_itself() {
        let r = parse("Home.$node").unwrap();
        assert_eq!(r, AllowFromRef::NodeItself("Home".parse().unwrap()));
        assert_eq!(r.to_string(), "Home.$node");
    }

    #[test]
    fn a_hub() {
        let r = parse("Home.$hub").unwrap();
        assert_eq!(r, AllowFromRef::Hub("Home".parse().unwrap()));
        assert_eq!(r.to_string(), "Home.$hub");
        // A plain local name, not the hub: a zone, device or hub client may
        // be called `hub`.
        assert_eq!(
            parse("Home.hub").unwrap(),
            AllowFromRef::nested("Home".parse().unwrap(), "hub".parse().unwrap())
        );
    }

    #[test]
    fn a_hub_is_named_by_its_node() {
        assert!(matches!(
            parse("$hub"),
            Err(ParseAllowFromRefError::InvalidIdentifier(_))
        ));
        for s in [".$hub", "$node.$hub", "-bad.$hub"] {
            assert!(
                matches!(
                    parse(s),
                    Err(ParseAllowFromRefError::InvalidNested(
                        ParseNestedIdentifierError::InvalidNode(_)
                    ))
                ),
                "{s}"
            );
        }
        assert!(matches!(
            parse("Home.$hub.lan"),
            Err(ParseAllowFromRefError::InvalidNested(
                ParseNestedIdentifierError::TooManyDots
            ))
        ));
    }

    #[test]
    fn a_node_itself_needs_a_node_name() {
        for s in [".$node", "$node.$node", "-bad.$node"] {
            assert!(
                matches!(
                    parse(s),
                    Err(ParseAllowFromRefError::InvalidNested(
                        ParseNestedIdentifierError::InvalidNode(_)
                    ))
                ),
                "{s}"
            );
        }
        // `$node` and `$hub` are the only keywords a node name qualifies, and
        // only as the last segment.
        assert!(matches!(
            parse("Home.$lan"),
            Err(ParseAllowFromRefError::InvalidNested(
                ParseNestedIdentifierError::InvalidLocal(_)
            ))
        ));
        assert!(matches!(
            parse("Home.$node.lan"),
            Err(ParseAllowFromRefError::InvalidNested(
                ParseNestedIdentifierError::TooManyDots
            ))
        ));
    }

    #[test]
    fn bare_identifier() {
        let r = parse("Home").unwrap();
        assert!(matches!(r, AllowFromRef::Bare(_)));
        assert_eq!(r.to_string(), "Home");
    }

    #[test]
    fn nested_identifier() {
        let r = parse("Home.lan").unwrap();
        assert!(matches!(r, AllowFromRef::Nested(_)));
        assert_eq!(r.to_string(), "Home.lan");
    }

    #[test]
    fn nested_constructor() {
        let node: Identifier = "Home".parse().unwrap();
        let local: Identifier = "lan".parse().unwrap();
        let r = AllowFromRef::nested(node, local);
        assert_eq!(r.to_string(), "Home.lan");
    }

    #[test]
    fn invalid_bare() {
        assert!(matches!(
            parse(""),
            Err(ParseAllowFromRefError::InvalidIdentifier(_))
        ));
        assert!(matches!(
            parse("-bad"),
            Err(ParseAllowFromRefError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn invalid_nested() {
        assert!(matches!(
            parse("a.b.c"),
            Err(ParseAllowFromRefError::InvalidNested(_))
        ));
        assert!(matches!(
            parse(".lan"),
            Err(ParseAllowFromRefError::InvalidNested(_))
        ));
    }

    #[test]
    fn display_roundtrip() {
        for s in ["$node", "Home.$node", "Home.$hub", "Home", "Home.lan"] {
            assert_eq!(parse(s).unwrap().to_string(), s);
        }
    }
}
