use std::{error::Error, fmt::Display, net::Ipv4Addr, str::FromStr};

use serde::Deserialize;

#[derive(Debug)]
pub enum ParseCidrError {
    IpParse(String, std::net::AddrParseError),
    InvalidPrefix(String),
    NoPrefix(String),
}

impl Display for ParseCidrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpParse(address, error) => write!(f, "invalid address '{}': {}", address, error),
            Self::InvalidPrefix(prefix) => write!(f, "invalid prefix {}: must be 0-32", prefix),
            Self::NoPrefix(address) => write!(f, "missing '/' in: '{}'", address),
        }
    }
}

impl Error for ParseCidrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpParse(_, e) => Some(e),
            _ => None,
        }
    }
}

fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8), ParseCidrError> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or(ParseCidrError::NoPrefix(s.to_owned()))?;

    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ParseCidrError::InvalidPrefix(s.to_owned()))?;

    if prefix > 32 {
        return Err(ParseCidrError::InvalidPrefix(s.to_owned()));
    }

    let addr = ip
        .parse()
        .map_err(|e| ParseCidrError::IpParse(s.to_owned(), e))?;

    Ok((addr, prefix))
}

fn mask_from_prefix(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

fn fmt_cidr(ip: &Ipv4Addr, prefix: u8, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{ip}/{prefix}")
}

fn validate_interface_addr(ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Interface, Ipv4InterfaceError> {
    let bits = ip.to_bits();
    let mask = mask_from_prefix(prefix);
    if prefix < 32 && (bits & mask) == bits {
        return Err(Ipv4InterfaceError::IsNetworkAddress(ip, prefix));
    }

    Ok(Ipv4Interface { addr: ip, prefix })
}

#[derive(Debug)]
pub enum Ipv4InterfaceError {
    ParseCidrError(ParseCidrError),
    IsNetworkAddress(Ipv4Addr, u8),
}

impl Display for Ipv4InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseCidrError(error) => error.fmt(f),
            Self::IsNetworkAddress(ip, prefix) => {
                fmt_cidr(ip, *prefix, f)?;
                write!(f, " is a network address, expected host address")
            }
        }
    }
}

impl Error for Ipv4InterfaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseCidrError(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct Ipv4Interface {
    addr: Ipv4Addr,
    prefix: u8,
}

impl FromStr for Ipv4Interface {
    type Err = Ipv4InterfaceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = parse_cidr(s).map_err(Ipv4InterfaceError::ParseCidrError)?;

        validate_interface_addr(addr, prefix)
    }
}

impl TryFrom<String> for Ipv4Interface {
    type Error = Ipv4InterfaceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl std::fmt::Display for Ipv4Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_cidr(&self.addr, self.prefix, f)
    }
}

impl Ipv4Interface {
    pub fn mask(&self) -> u32 {
        mask_from_prefix(self.prefix)
    }

    pub fn network(&self) -> Ipv4Network {
        Ipv4Network {
            addr: Ipv4Addr::from_bits(self.addr.to_bits() & self.mask()),
            prefix: self.prefix,
        }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn from_ip(ip: Ipv4Addr, prefix: u8) -> Result<Self, Ipv4InterfaceError> {
        if prefix > 32 {
            return Err(Ipv4InterfaceError::ParseCidrError(
                ParseCidrError::InvalidPrefix(prefix.to_string()),
            ));
        }

        validate_interface_addr(ip, prefix)
    }

    pub fn is_in_same_network(&self, ip: Ipv4Addr) -> bool {
        let mask = self.mask();

        (ip.to_bits() & mask) == (self.addr.to_bits() & mask)
    }

    pub fn host(ip: Ipv4Addr) -> Self {
        Self {
            addr: ip,
            prefix: 32,
        }
    }
}

#[derive(Debug)]
pub enum Ipv4NetworkError {
    ParseCidrError(ParseCidrError),
    NotANetworkAddress(Ipv4Addr, u8),
}

impl Display for Ipv4NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseCidrError(error) => error.fmt(f),
            Self::NotANetworkAddress(ip, prefix) => {
                fmt_cidr(ip, *prefix, f)?;
                write!(f, " is not a network address")
            }
        }
    }
}

impl Error for Ipv4NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseCidrError(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Ipv4Network {
    addr: Ipv4Addr,
    prefix: u8,
}

impl FromStr for Ipv4Network {
    type Err = Ipv4NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = parse_cidr(s).map_err(Ipv4NetworkError::ParseCidrError)?;
        let bits = addr.to_bits();
        let mask = mask_from_prefix(prefix);

        if (bits & mask) != bits {
            return Err(Ipv4NetworkError::NotANetworkAddress(addr, prefix));
        }

        Ok(Self { addr, prefix })
    }
}

impl TryFrom<String> for Ipv4Network {
    type Error = Ipv4NetworkError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for Ipv4Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_cidr(&self.addr, self.prefix, f)
    }
}

impl Ipv4Network {
    pub fn ip(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn mask(&self) -> u32 {
        mask_from_prefix(self.prefix)
    }

    pub fn host(ip: Ipv4Addr) -> Self {
        Self {
            addr: ip,
            prefix: 32,
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (self.mask() & ip.to_bits()) == self.addr.to_bits()
    }
}
