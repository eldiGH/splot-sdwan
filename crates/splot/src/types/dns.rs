//! Names in DNS: a host name, and its labels.

use std::{fmt, str::FromStr};

use serde::Deserialize;

/// A DNS name: labels of letters, digits and hyphens, separated by dots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
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

/// One label of a DNS name, the name a host is given by DHCP: letters, digits
/// and hyphens, not at either end, at most 63 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct DnsLabel(String);

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

impl FromStr for DnsLabel {
    type Err = ParseHostnameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        check_label(s)?;

        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for Hostname {
    type Error = ParseHostnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for DnsLabel {
    type Error = ParseHostnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Hostname {
    /// `label` in front of this name: `printer.home.example.org`. Too long a
    /// name, or a label that isn't one, is an error.
    pub fn with_label(&self, label: &str) -> Result<Self, ParseHostnameError> {
        format!("{label}.{}", self.0).parse()
    }

    /// Whether this name is `domain` or lies inside it, case aside.
    pub fn is_within(&self, domain: &Self) -> bool {
        let (name, domain) = (self.0.to_ascii_lowercase(), domain.0.to_ascii_lowercase());

        name == domain || name.ends_with(&format!(".{domain}"))
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DnsLabel {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(s: &str) -> Result<DnsLabel, ParseHostnameError> {
        s.parse()
    }

    #[test]
    fn a_name_with_a_label_in_front() {
        let domain: Hostname = "home.example.org".parse().unwrap();
        assert_eq!(
            domain.with_label("printer").unwrap().to_string(),
            "printer.home.example.org"
        );
        assert_eq!(
            domain.with_label("my_printer"),
            Err(ParseHostnameError::InvalidCharacter {
                found: '_',
                label: "my_printer".to_string()
            })
        );
        let long: Hostname = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61))
            .parse()
            .unwrap();
        assert!(matches!(
            long.with_label("b"),
            Err(ParseHostnameError::TooLong { .. })
        ));
    }

    #[test]
    fn a_name_is_within_a_domain_it_ends_in_case_aside() {
        let domain: Hostname = "home.example.org".parse().unwrap();
        let within = |name: &str| name.parse::<Hostname>().unwrap().is_within(&domain);

        assert!(within("home.example.org"));
        assert!(within("wg.Home.Example.org"));
        assert!(within("a.b.home.example.org"));
        assert!(!within("example.org"));
        assert!(!within("myhome.example.org"));
        assert!(!within("home.example.org.uk"));
    }

    #[test]
    fn a_label_is_kept_as_written() {
        for name in ["printer", "Printer", "srv-01", "a", "1", "123"] {
            assert_eq!(label(name).unwrap().to_string(), name);
        }
        assert!(label(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn a_label_has_no_dot_and_none_of_what_a_hostname_refuses() {
        assert_eq!(
            label("my_printer"),
            Err(ParseHostnameError::InvalidCharacter {
                found: '_',
                label: "my_printer".to_string()
            })
        );
        assert_eq!(
            label("printer.lan"),
            Err(ParseHostnameError::InvalidCharacter {
                found: '.',
                label: "printer.lan".to_string()
            })
        );
        assert_eq!(
            label("printer-"),
            Err(ParseHostnameError::HyphenAtEdge {
                label: "printer-".to_string()
            })
        );
        assert_eq!(
            label(&"a".repeat(64)),
            Err(ParseHostnameError::LabelTooLong {
                label: "a".repeat(64)
            })
        );
        assert_eq!(label(""), Err(ParseHostnameError::EmptyLabel));
    }
}
