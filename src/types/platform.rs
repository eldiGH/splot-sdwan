//! A node's platform: the OS it runs and the program behind each concern splot
//! can manage there.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, de};

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

/// What splot can manage on a node, each through a program of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Concern {
    WireGuard,
    Firewall,
    Dhcp,
    Dns,
}

/// A program that carries out one concern on a node.
pub trait Program: Copy + Eq + fmt::Display + 'static {
    const CONCERN: Concern;
    /// Every program splot knows for the concern.
    const ALL: &'static [Self];

    /// Whether splot can manage the concern with it on `os`.
    fn runs_on(self, os: Os) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardProgram {
    Netifd,
    WgQuick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProgram {
    Fw4,
    Nftables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpProgram {
    Dnsmasq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProgram {
    Dnsmasq,
}

impl Program for WireGuardProgram {
    const CONCERN: Concern = Concern::WireGuard;
    const ALL: &'static [Self] = &[Self::Netifd, Self::WgQuick];

    fn runs_on(self, os: Os) -> bool {
        match self {
            Self::Netifd => os == Os::OpenWrt,
            Self::WgQuick => os == Os::Linux,
        }
    }
}

impl Program for FirewallProgram {
    const CONCERN: Concern = Concern::Firewall;
    const ALL: &'static [Self] = &[Self::Fw4, Self::Nftables];

    fn runs_on(self, os: Os) -> bool {
        match self {
            Self::Fw4 => os == Os::OpenWrt,
            Self::Nftables => os == Os::Linux,
        }
    }
}

impl Program for DhcpProgram {
    const CONCERN: Concern = Concern::Dhcp;
    const ALL: &'static [Self] = &[Self::Dnsmasq];

    fn runs_on(self, _: Os) -> bool {
        match self {
            Self::Dnsmasq => true,
        }
    }
}

impl Program for DnsProgram {
    const CONCERN: Concern = Concern::Dns;
    const ALL: &'static [Self] = &[Self::Dnsmasq];

    fn runs_on(self, _: Os) -> bool {
        match self {
            Self::Dnsmasq => true,
        }
    }
}

/// What a node's `platform` says for one concern: the program splot manages it
/// with, or `none`: splot leaves the concern alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting<P> {
    Program(P),
    None,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{found:?} isn't a {concern} program splot knows: {known}, or none")]
pub struct ParseSettingError {
    concern: Concern,
    found: String,
    known: String,
}

/// `none` in the config: splot leaves the concern alone.
const NONE: &str = "none";

/// `a, b, c`.
pub fn names<P: Program>(programs: impl IntoIterator<Item = P>) -> String {
    let names: Vec<String> = programs.into_iter().map(|p| p.to_string()).collect();
    names.join(", ")
}

impl<P: Program> FromStr for Setting<P> {
    type Err = ParseSettingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == NONE {
            return Ok(Self::None);
        }

        P::ALL
            .iter()
            .find(|program| program.to_string() == s)
            .map(|program| Self::Program(*program))
            .ok_or_else(|| ParseSettingError {
                concern: P::CONCERN,
                found: s.to_owned(),
                known: names(P::ALL.iter().copied()),
            })
    }
}

impl<'de, P: Program> Deserialize<'de> for Setting<P> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
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

impl fmt::Display for Concern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireGuard => write!(f, "wireguard"),
            Self::Firewall => write!(f, "firewall"),
            Self::Dhcp => write!(f, "dhcp"),
            Self::Dns => write!(f, "dns"),
        }
    }
}

impl fmt::Display for WireGuardProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netifd => write!(f, "netifd"),
            Self::WgQuick => write!(f, "wg-quick"),
        }
    }
}

impl fmt::Display for FirewallProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fw4 => write!(f, "fw4"),
            Self::Nftables => write!(f, "nftables"),
        }
    }
}

impl fmt::Display for DhcpProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dnsmasq => write!(f, "dnsmasq"),
        }
    }
}

impl fmt::Display for DnsProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dnsmasq => write!(f, "dnsmasq"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<P: Program>(s: &str) -> Result<Setting<P>, ParseSettingError> {
        s.parse()
    }

    #[test]
    fn a_setting_is_a_program_by_its_name_or_none() {
        assert_eq!(
            parse("netifd"),
            Ok(Setting::Program(WireGuardProgram::Netifd))
        );
        assert_eq!(
            parse("wg-quick"),
            Ok(Setting::Program(WireGuardProgram::WgQuick))
        );
        assert_eq!(parse("fw4"), Ok(Setting::Program(FirewallProgram::Fw4)));
        assert_eq!(
            parse("nftables"),
            Ok(Setting::Program(FirewallProgram::Nftables))
        );
        assert_eq!(parse("dnsmasq"), Ok(Setting::Program(DhcpProgram::Dnsmasq)));
        assert_eq!(parse("dnsmasq"), Ok(Setting::Program(DnsProgram::Dnsmasq)));

        assert_eq!(parse::<WireGuardProgram>("none"), Ok(Setting::None));
        assert_eq!(parse::<DnsProgram>("none"), Ok(Setting::None));
    }

    #[test]
    fn an_os_is_known_by_the_name_the_config_gives_it() {
        for os in Os::ALL {
            assert_eq!(os.to_string().parse(), Ok(os));
            let yaml: Os = serde_norway::from_str(&os.to_string()).unwrap();
            assert_eq!(yaml, os);
        }
        assert!("OpenWrt".parse::<Os>().is_err());
    }

    #[test]
    fn a_program_of_another_concern_is_unknown() {
        assert_eq!(
            parse::<WireGuardProgram>("dnsmasq"),
            Err(ParseSettingError {
                concern: Concern::WireGuard,
                found: "dnsmasq".to_owned(),
                known: "netifd, wg-quick".to_owned(),
            })
        );
        // Names are matched as written.
        assert!(parse::<FirewallProgram>("FW4").is_err());
        assert!(parse::<FirewallProgram>("None").is_err());
    }

    #[test]
    fn each_program_runs_where_splot_can_manage_it() {
        use Os::{Linux, OpenWrt};

        let on = |program: &dyn Fn(Os) -> bool| [OpenWrt, Linux].map(program);

        assert_eq!(
            on(&|os| WireGuardProgram::Netifd.runs_on(os)),
            [true, false]
        );
        assert_eq!(
            on(&|os| WireGuardProgram::WgQuick.runs_on(os)),
            [false, true]
        );
        assert_eq!(on(&|os| FirewallProgram::Fw4.runs_on(os)), [true, false]);
        assert_eq!(
            on(&|os| FirewallProgram::Nftables.runs_on(os)),
            [false, true]
        );
        assert_eq!(on(&|os| DhcpProgram::Dnsmasq.runs_on(os)), [true, true]);
        assert_eq!(on(&|os| DnsProgram::Dnsmasq.runs_on(os)), [true, true]);
    }
}
