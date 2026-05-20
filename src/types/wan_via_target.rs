use std::{fmt, str::FromStr};

use serde::Deserialize;

use crate::types::identifier::{
    Identifier, NestedIdentifier, ParseIdentifierError, ParseNestedIdentifierError,
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
