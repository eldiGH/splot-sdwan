//! Names in DNS: a host name, and its labels.

use std::{fmt, str::FromStr};

/// A DNS name: labels of letters, digits and hyphens, separated by dots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseHostnameError {
    #[error("{len} characters long, at most {} allowed", MAX_NAME_LEN)]
    TooLong { len: usize },
    #[error("empty label (a dot at either end, or two in a row)")]
    EmptyLabel,
    #[error("label {label:?} is longer than {} characters", MAX_LABEL_LEN)]
    LabelTooLong { label: String },
    #[error("invalid character {found:?} in {label:?} (only letters, digits and hyphens)")]
    InvalidCharacter { found: char, label: String },
    #[error("label {label:?} starts or ends with a hyphen")]
    HyphenAtEdge { label: String },
    #[error("the last label is all digits")]
    NumericLastLabel,
}

/// The longest name DNS carries, written without a trailing dot.
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

fn check_label(label: &str) -> Result<(), ParseHostnameError> {
    if label.is_empty() {
        return Err(ParseHostnameError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(ParseHostnameError::LabelTooLong {
            label: label.to_string(),
        });
    }
    if let Some(found) = label
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-')
    {
        return Err(ParseHostnameError::InvalidCharacter {
            found,
            label: label.to_string(),
        });
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseHostnameError::HyphenAtEdge {
            label: label.to_string(),
        });
    }

    Ok(())
}

impl FromStr for Hostname {
    type Err = ParseHostnameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_NAME_LEN {
            return Err(ParseHostnameError::TooLong { len: s.len() });
        }

        s.split('.').try_for_each(check_label)?;

        // No top-level domain is all digits, so such a name is a mistyped IP.
        let last = s.rsplit('.').next().unwrap_or(s);
        if last.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseHostnameError::NumericLastLabel);
        }

        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
