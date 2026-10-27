//! Where splot reaches a node over ssh.

use std::{fmt, str::FromStr};

use serde::Deserialize;

/// What splot gives `ssh` to reach a node, as it is: `root@192.168.1.1`, a
/// host of `~/.ssh/config`, `ssh://root@router:2222`. Never read as an option.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct SshDestination(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseSshDestinationError {
    #[error("empty")]
    Empty,
    #[error("starts with '-', which ssh would read as an option")]
    Option,
    #[error("contains {0:?}: no spaces or control characters")]
    InvalidCharacter(char),
}

impl SshDestination {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SshDestination {
    type Err = ParseSshDestinationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseSshDestinationError::Empty);
        }
        if s.starts_with('-') {
            return Err(ParseSshDestinationError::Option);
        }
        if let Some(found) = s.chars().find(|c| c.is_whitespace() || c.is_control()) {
            return Err(ParseSshDestinationError::InvalidCharacter(found));
        }

        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for SshDestination {
    type Error = ParseSshDestinationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for SshDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<SshDestination, ParseSshDestinationError> {
        s.parse()
    }

    #[test]
    fn anything_ssh_takes_as_a_destination_is_kept_as_it_is() {
        for destination in [
            "root@192.168.1.1",
            "router",
            "root@cabin.example.net",
            "ssh://root@router:2222",
            "root@[fe80::1%eth0]",
        ] {
            assert_eq!(parse(destination).unwrap().as_str(), destination);
        }
    }

    #[test]
    fn a_destination_ssh_would_read_otherwise_is_refused() {
        assert_eq!(parse(""), Err(ParseSshDestinationError::Empty));
        assert_eq!(
            parse("-oProxyCommand=sh"),
            Err(ParseSshDestinationError::Option)
        );
        assert_eq!(
            parse("root@router -p 2222"),
            Err(ParseSshDestinationError::InvalidCharacter(' '))
        );
        assert_eq!(
            parse("root@router\n"),
            Err(ParseSshDestinationError::InvalidCharacter('\n'))
        );
        assert_eq!(
            parse("root@\trouter"),
            Err(ParseSshDestinationError::InvalidCharacter('\t'))
        );
        assert_eq!(
            parse("root@router\u{7}"),
            Err(ParseSshDestinationError::InvalidCharacter('\u{7}'))
        );
    }
}
