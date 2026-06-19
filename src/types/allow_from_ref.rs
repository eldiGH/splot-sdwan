use std::{fmt, str::FromStr};

use serde::Deserialize;

use crate::{
    consts,
    types::identifier::{
        Identifier, NestedIdentifier, ParseIdentifierError, ParseNestedIdentifierError,
    },
};

#[derive(Debug)]
pub enum ParseAllowFromRefError {
    InvalidIdentifier(ParseIdentifierError),
    InvalidNested(ParseNestedIdentifierError),
}

impl fmt::Display for ParseAllowFromRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(e) => write!(f, "invalid allowFrom reference: {e}"),
            Self::InvalidNested(e) => write!(f, "invalid qualified allowFrom reference: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum AllowFromRef {
    Bare(Identifier),
    Nested(NestedIdentifier),
    SelfNode,
}

impl FromStr for AllowFromRef {
    type Err = ParseAllowFromRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == consts::CURRENT_NODE_IDENTIFIER {
            return Ok(Self::SelfNode);
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
        for s in ["$node", "Home", "Home.lan"] {
            assert_eq!(parse(s).unwrap().to_string(), s);
        }
    }
}
