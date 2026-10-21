//! The operating system a node runs.

use std::{fmt, str::FromStr};

use serde::Deserialize;

/// The operating system a node runs.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    OpenWrt,
    Linux,
}

impl Os {
    /// Every OS splot knows.
    pub const ALL: [Self; 2] = [Self::OpenWrt, Self::Linux];
}

/// The OS named on the command line (`splot init --os`), which splot doesn't
/// know.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{found:?} isn't an OS splot knows: {known}")]
pub struct ParseOsError {
    found: String,
    known: String,
}

impl FromStr for Os {
    type Err = ParseOsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|os| os.to_string() == s)
            .ok_or_else(|| {
                let known: Vec<String> = Self::ALL.iter().map(Os::to_string).collect();
                ParseOsError {
                    found: s.to_owned(),
                    known: known.join(", "),
                }
            })
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenWrt => write!(f, "openwrt"),
            Self::Linux => write!(f, "linux"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_os_is_known_by_the_name_the_config_gives_it() {
        for os in Os::ALL {
            assert_eq!(os.to_string().parse(), Ok(os));
            let yaml: Os = serde_norway::from_str(&os.to_string()).unwrap();
            assert_eq!(yaml, os);
        }
        assert!("OpenWrt".parse::<Os>().is_err());
    }
}
