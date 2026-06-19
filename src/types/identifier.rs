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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Identifier, ParseIdentifierError> {
        s.parse::<Identifier>()
    }

    fn parse_nested(s: &str) -> Result<NestedIdentifier, ParseNestedIdentifierError> {
        s.parse::<NestedIdentifier>()
    }

    #[test]
    fn valid_identifiers() {
        for s in ["abc", "a-b_c", "Node1", "1abc", "A", "9"] {
            assert_eq!(parse(s).unwrap().as_ref(), s);
        }
    }

    #[test]
    fn empty_is_rejected() {
        assert!(matches!(parse(""), Err(ParseIdentifierError::Empty)));
    }

    #[test]
    fn invalid_first_character() {
        // leading non-alphanumeric is rejected at position 0
        for s in ["-abc", "_abc", ".abc"] {
            assert!(matches!(
                parse(s),
                Err(ParseIdentifierError::InvalidCharacter { position: 0, .. })
            ));
        }
    }

    #[test]
    fn invalid_middle_character_reports_position() {
        assert!(matches!(
            parse("ab c"),
            Err(ParseIdentifierError::InvalidCharacter {
                found: ' ',
                position: 2
            })
        ));
        assert!(matches!(
            parse("ab.c"),
            Err(ParseIdentifierError::InvalidCharacter {
                found: '.',
                position: 2
            })
        ));
    }

    #[test]
    fn reserved_prefix_is_rejected() {
        assert!(matches!(
            parse("spl_foo"),
            Err(ParseIdentifierError::ReservedPrefix {
                prefix: consts::SPLOT_SECTION_PREFIX
            })
        ));
        // "spl" without the underscore is a normal identifier
        assert!(parse("spl").is_ok());
    }

    #[test]
    fn display_and_into_string_roundtrip() {
        let id = parse("Home").unwrap();
        assert_eq!(id.to_string(), "Home");
        assert_eq!(String::from(id), "Home");
    }

    #[test]
    fn nested_valid() {
        let nested = parse_nested("Home.lan").unwrap();
        assert_eq!(nested.node.as_ref(), "Home");
        assert_eq!(nested.local.as_ref(), "lan");
        assert_eq!(nested.to_string(), "Home.lan");
    }

    #[test]
    fn nested_missing_dot() {
        assert!(matches!(
            parse_nested("Homelan"),
            Err(ParseNestedIdentifierError::MissingDot)
        ));
    }

    #[test]
    fn nested_too_many_dots() {
        assert!(matches!(
            parse_nested("a.b.c"),
            Err(ParseNestedIdentifierError::TooManyDots)
        ));
    }

    #[test]
    fn nested_invalid_segments() {
        assert!(matches!(
            parse_nested("-bad.lan"),
            Err(ParseNestedIdentifierError::InvalidNode(_))
        ));
        // empty local segment surfaces as an invalid local
        assert!(matches!(
            parse_nested("Home."),
            Err(ParseNestedIdentifierError::InvalidLocal(_))
        ));
        // reserved prefix on the node segment
        assert!(matches!(
            parse_nested("spl_x.lan"),
            Err(ParseNestedIdentifierError::InvalidNode(_))
        ));
    }
}
