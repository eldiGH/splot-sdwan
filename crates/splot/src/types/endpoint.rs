//! A node's endpoint: where other peers dial it.

use std::{fmt, net::Ipv4Addr, str::FromStr};

use serde::Deserialize;

/// Where other peers dial a node: an IPv4 address, or a DNS name that resolves
/// to one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum EndpointHost {
    Ip(Ipv4Addr),
    Name(Hostname),
}

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

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("neither an IPv4 address nor a host name: {0}")]
pub struct ParseEndpointHostError(ParseHostnameError);

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

impl FromStr for EndpointHost {
    type Err = ParseEndpointHostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse() {
            return Ok(Self::Ip(ip));
        }

        s.parse().map(Self::Name).map_err(ParseEndpointHostError)
    }
}

impl TryFrom<String> for EndpointHost {
    type Error = ParseEndpointHostError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for EndpointHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Name(name) => name.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<EndpointHost, ParseHostnameError> {
        s.parse::<EndpointHost>()
            .map_err(|ParseEndpointHostError(err)| err)
    }

    fn label(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn an_ipv4_address_is_an_ip() {
        assert_eq!(
            parse("203.0.113.10"),
            Ok(EndpointHost::Ip(Ipv4Addr::new(203, 0, 113, 10)))
        );
    }

    #[test]
    fn a_host_name_is_kept_as_written() {
        for name in [
            "wg.cabin.example.net",
            "Cabin.Example.NET",
            "cam-2-1.example.net",
            "1.example.net",
            "nas01",
        ] {
            let host = parse(name).unwrap();
            assert!(matches!(host, EndpointHost::Name(_)), "{name}");
            assert_eq!(host.to_string(), name);
        }
    }

    #[test]
    fn labels_and_names_up_to_the_dns_limits() {
        let label_63 = "a".repeat(63);
        assert!(parse(&format!("{label_63}.example.net")).is_ok());

        // Three labels of 63, one of 61 and three dots.
        let name_253 = format!("{0}.{0}.{0}.{1}", label_63, "a".repeat(61));
        assert_eq!(name_253.len(), 253);
        assert!(parse(&name_253).is_ok());

        let name_254 = format!("{name_253}a");
        assert_eq!(
            parse(&name_254),
            Err(ParseHostnameError::TooLong { len: 254 })
        );

        let label_64 = "a".repeat(64);
        assert_eq!(
            parse(&format!("{label_64}.example.net")),
            Err(ParseHostnameError::LabelTooLong { label: label_64 })
        );
    }

    #[test]
    fn empty_labels() {
        for name in ["", ".example.net", "example.net.", "wg..example.net"] {
            assert_eq!(parse(name), Err(ParseHostnameError::EmptyLabel), "{name:?}");
        }
    }

    #[test]
    fn only_letters_digits_and_hyphens() {
        assert_eq!(
            parse("wg_cabin.example.net"),
            Err(ParseHostnameError::InvalidCharacter {
                found: '_',
                label: label("wg_cabin")
            })
        );
        // The port has its own key (`listenPort`).
        assert_eq!(
            parse("cabin.example.net:51820"),
            Err(ParseHostnameError::InvalidCharacter {
                found: ':',
                label: label("net:51820")
            })
        );
    }

    #[test]
    fn no_hyphen_at_either_end_of_a_label() {
        for (name, bad) in [("-wg.example.net", "-wg"), ("wg-.example.net", "wg-")] {
            assert_eq!(
                parse(name),
                Err(ParseHostnameError::HyphenAtEdge { label: label(bad) }),
                "{name}"
            );
        }
    }

    #[test]
    fn a_mistyped_ip_is_no_host_name() {
        // All-digit labels would pass as a name, so a typo in an IP would
        // become a name that never resolves. No top-level domain is all digits.
        for name in ["203.0.113.300", "203.0.113", "12345"] {
            assert_eq!(
                parse(name),
                Err(ParseHostnameError::NumericLastLabel),
                "{name}"
            );
        }
    }

    #[test]
    fn the_error_says_what_was_expected() {
        let err = "wg_cabin.example.net".parse::<EndpointHost>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "neither an IPv4 address nor a host name: invalid character '_' in \"wg_cabin\" \
             (only letters, digits and hyphens)"
        );
    }
}
