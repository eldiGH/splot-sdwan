//! A network interface of a Linux node, which nftables matches a zone by.

use std::{fmt, str::FromStr};

use serde::Deserialize;

/// The longest name Linux gives an interface (`IFNAMSIZ`, less its NUL).
const MAX_LEN: usize = 15;

/// An interface's name: `eth0`, `br-lan`, `eth0.20`. One Linux takes (at most
/// 15 characters, not `.` or `..`), in the characters interface names are
/// written with: letters, digits, `.`, `-` and `_`. So none nftables would read
/// otherwise in a name (a `*` is a wildcard there, a `"` ends it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct InterfaceName(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseInterfaceNameError {
    #[error("empty")]
    Empty,
    #[error("{0} characters long: Linux names an interface in at most {MAX_LEN}")]
    TooLong(usize),
    #[error("isn't a name Linux gives an interface")]
    Dots,
    #[error("contains {0:?}: letters, digits, '.', '-' and '_' only")]
    InvalidCharacter(char),
}

impl InterfaceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for InterfaceName {
    type Err = ParseInterfaceNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseInterfaceNameError::Empty);
        }
        if let Some(found) = s
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        {
            return Err(ParseInterfaceNameError::InvalidCharacter(found));
        }
        if s.len() > MAX_LEN {
            return Err(ParseInterfaceNameError::TooLong(s.len()));
        }
        if s == "." || s == ".." {
            return Err(ParseInterfaceNameError::Dots);
        }

        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for InterfaceName {
    type Error = ParseInterfaceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<InterfaceName, ParseInterfaceNameError> {
        s.parse()
    }

    #[test]
    fn the_names_linux_gives_interfaces_are_kept_as_they_are() {
        for name in [
            "eth0",
            "br-lan",
            "eth0.20",
            "enp0s31f6",
            "wg_home",
            "a",
            "abcdefghijklmno",
        ] {
            assert_eq!(parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn a_name_linux_wouldnt_take_is_refused() {
        assert_eq!(parse(""), Err(ParseInterfaceNameError::Empty));
        assert_eq!(
            parse("abcdefghijklmnop"),
            Err(ParseInterfaceNameError::TooLong(16))
        );
        assert_eq!(parse("."), Err(ParseInterfaceNameError::Dots));
        assert_eq!(parse(".."), Err(ParseInterfaceNameError::Dots));
        // Linux refuses these.
        for (name, found) in [("eth/0", '/'), ("eth:0", ':'), ("eth 0", ' ')] {
            assert_eq!(
                parse(name),
                Err(ParseInterfaceNameError::InvalidCharacter(found))
            );
        }
    }

    #[test]
    fn a_name_nftables_would_read_otherwise_is_refused() {
        for (name, found) in [("eth*", '*'), ("eth0\"", '"'), ("eth\\0", '\\')] {
            assert_eq!(
                parse(name),
                Err(ParseInterfaceNameError::InvalidCharacter(found))
            );
        }
    }
}
