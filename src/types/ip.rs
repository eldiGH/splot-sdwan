use std::{fmt::Display, net::Ipv4Addr, str::FromStr};

use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct Ipv4Interface {
    addr: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug)]
pub enum Ipv4InterfaceErrors {
    IpParse(String, std::net::AddrParseError),
    InvalidPrefix(String),
    NoPrefix(String),
}

impl Display for Ipv4InterfaceErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpParse(address, error) => write!(f, "invalid address '{}': {}", address, error),
            Self::InvalidPrefix(prefix) => write!(f, "invalid prefix {}: must be 0-32", prefix),
            Self::NoPrefix(address) => write!(f, "missing '/' in: '{}'", address),
        }
    }
}

impl std::error::Error for Ipv4InterfaceErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpParse(_, e) => Some(e),
            _ => None,
        }
    }
}

impl FromStr for Ipv4Interface {
    type Err = Ipv4InterfaceErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = s
            .split_once('/')
            .ok_or(Ipv4InterfaceErrors::NoPrefix(s.to_owned()))?;

        let prefix: u8 = prefix
            .parse()
            .map_err(|_| Ipv4InterfaceErrors::InvalidPrefix(s.to_owned()))?;

        if prefix > 32 {
            return Err(Ipv4InterfaceErrors::InvalidPrefix(s.to_owned()));
        }

        let addr = ip
            .parse()
            .map_err(|e| Ipv4InterfaceErrors::IpParse(s.to_owned(), e))?;

        Ok(Ipv4Interface { addr, prefix })
    }
}

impl TryFrom<String> for Ipv4Interface {
    type Error = Ipv4InterfaceErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl std::fmt::Display for Ipv4Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Ipv4Interface {
    pub fn from_ip(ip: Ipv4Addr, prefix: u8) -> Result<Self, Ipv4InterfaceErrors> {
        if prefix > 32 {
            return Err(Ipv4InterfaceErrors::InvalidPrefix(prefix.to_string()));
        }

        Ok(Self { addr: ip, prefix })
    }

    pub fn network(&self) -> Ipv4Network {
        let mask = self.mask();
        let addr = Ipv4Addr::from_bits(self.addr.to_bits() & mask);

        Ipv4Network(Self {
            addr,
            prefix: self.prefix,
        })
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = self.mask();

        (ip.to_bits() & mask) == (self.addr.to_bits() & mask)
    }

    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix)
        }
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn to_bits(self) -> u32 {
        self.addr.to_bits()
    }
}

#[derive(Debug)]
pub enum Ipv4NetworkErrors {
    Ipv4InterfaceError(Ipv4InterfaceErrors),
    NotANetworkAddress(Ipv4Interface),
}

impl Display for Ipv4NetworkErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4InterfaceError(interface_error) => interface_error.fmt(f),
            Self::NotANetworkAddress(interface) => write!(f, "not a network address: {interface}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Ipv4Network(Ipv4Interface);

impl FromStr for Ipv4Network {
    type Err = Ipv4NetworkErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_interface: Ipv4Interface =
            s.parse().map_err(Ipv4NetworkErrors::Ipv4InterfaceError)?;
        let bits = ip_interface.to_bits();

        if (bits & ip_interface.mask()) != bits {
            return Err(Ipv4NetworkErrors::NotANetworkAddress(ip_interface));
        }

        Ok(Self(ip_interface))
    }
}

impl TryFrom<String> for Ipv4Network {
    type Error = Ipv4NetworkErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for Ipv4Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Ipv4Network {
    pub fn ip(&self) -> Ipv4Addr {
        self.0.ip()
    }

    pub fn prefix(&self) -> u8 {
        self.0.prefix()
    }
}
