use std::net::Ipv4Addr;

use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct IpSubnet {
    addr: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug)]
pub enum IpSubnetErrors {
    IpParse(String, std::net::AddrParseError),
    InvalidPrefix(String),
    NoPrefix(String),
}

impl std::fmt::Display for IpSubnetErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpParse(address, error) => write!(f, "invalid address '{}': {}", address, error),
            Self::InvalidPrefix(prefix) => write!(f, "invalid prefix {}: must be 0-32", prefix),
            Self::NoPrefix(address) => write!(f, "missing '/' in: '{}'", address),
        }
    }
}

impl std::error::Error for IpSubnetErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpParse(_, e) => Some(e),
            _ => None,
        }
    }
}

impl TryFrom<String> for IpSubnet {
    type Error = IpSubnetErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or(IpSubnetErrors::NoPrefix(value.clone()))?;

        let prefix: u8 = prefix
            .parse()
            .map_err(|_| IpSubnetErrors::InvalidPrefix(value.clone()))?;

        if prefix > 32 {
            return Err(IpSubnetErrors::InvalidPrefix(value.clone()));
        }

        let addr = ip
            .parse()
            .map_err(|e| IpSubnetErrors::IpParse(value.clone(), e))?;

        Ok(IpSubnet { addr, prefix })
    }
}

impl std::fmt::Display for IpSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl IpSubnet {
    pub fn from_ip(ip: Ipv4Addr, prefix: u8) -> Result<Self, IpSubnetErrors> {
        if prefix > 32 {
            return Err(IpSubnetErrors::InvalidPrefix(prefix.to_string()));
        }

        Ok(Self { addr: ip, prefix })
    }

    pub fn network(&self) -> Self {
        let mask = self.mask();
        let addr = Ipv4Addr::from_bits(self.addr.to_bits() & mask);

        Self {
            addr,
            prefix: self.prefix,
        }
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
}
