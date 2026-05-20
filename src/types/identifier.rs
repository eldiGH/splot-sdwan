use std::{borrow::Borrow, fmt, str::FromStr};

use serde::Deserialize;

use crate::consts;

#[derive(Debug)]
pub enum ParseIdentifierError {
    Empty,
    InvalidCharacter { found: char, position: usize },
    ReservedPrefix { prefix: &'static str },
}

impl fmt::Display for ParseIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "identifier is empty"),
            Self::InvalidCharacter { found, position } => {
                write!(f, "invalid character {found:?} at position {position}")
            }
            Self::ReservedPrefix { prefix } => {
                write!(f, "identifier starts with reserved prefix {prefix:?}")
            }
        }
    }
}

fn validate_identifier(identifier: &str) -> Result<(), ParseIdentifierError> {
    let mut chars = identifier.chars().enumerate();

    let Some((pos, first)) = chars.next() else {
        return Err(ParseIdentifierError::Empty);
    };

    if !first.is_ascii_alphanumeric() {
        return Err(ParseIdentifierError::InvalidCharacter {
            found: first,
            position: pos,
        });
    }

    for (pos, char) in chars {
        if char.is_ascii_alphanumeric() || char == '-' || char == '_' {
            continue;
        }

        return Err(ParseIdentifierError::InvalidCharacter {
            found: char,
            position: pos,
        });
    }

    if identifier.starts_with(consts::SPLOT_SECTION_PREFIX) {
        return Err(ParseIdentifierError::ReservedPrefix {
            prefix: consts::SPLOT_SECTION_PREFIX,
        });
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Identifier(String);

impl FromStr for Identifier {
    type Err = ParseIdentifierError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_identifier(s)?;

        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for Identifier {
    type Error = ParseIdentifierError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_identifier(&value)?;

        Ok(Self(value))
    }
}

impl Borrow<str> for Identifier {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Identifier {
    fn eq(&self, other: &&str) -> bool {
        &self.0 == other
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.0
    }
}

#[derive(Debug)]
pub enum ParseNestedIdentifierError {
    MissingDot,
    TooManyDots,
    InvalidNode(ParseIdentifierError),
    InvalidLocal(ParseIdentifierError),
}

impl fmt::Display for ParseNestedIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDot => write!(
                f,
                "missing '.' separator — qualified names have the form 'Node.Local'"
            ),
            Self::TooManyDots => write!(
                f,
                "too many '.' separators — qualified names have exactly two segments"
            ),
            Self::InvalidNode(e) => write!(f, "invalid node segment: {e}"),
            Self::InvalidLocal(e) => write!(f, "invalid local segment: {e}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct NestedIdentifier {
    pub node: Identifier,
    pub local: Identifier,
}

impl FromStr for NestedIdentifier {
    type Err = ParseNestedIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (node, local) = s
            .split_once('.')
            .ok_or(ParseNestedIdentifierError::MissingDot)?;

        if local.contains('.') {
            return Err(ParseNestedIdentifierError::TooManyDots);
        }

        Ok(NestedIdentifier {
            node: node
                .parse()
                .map_err(ParseNestedIdentifierError::InvalidNode)?,
            local: local
                .parse()
                .map_err(ParseNestedIdentifierError::InvalidLocal)?,
        })
    }
}

impl TryFrom<String> for NestedIdentifier {
    type Error = ParseNestedIdentifierError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for NestedIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.node, self.local)
    }
}
