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
    let network = Ipv4Network {
        addr: Ipv4Addr::from_bits(ip.to_bits() & mask_from_prefix(prefix)),
        prefix,
    };

    match network.reserved_address(ip) {
        Some(ReservedAddress::Network) => Err(Ipv4InterfaceError::IsNetworkAddress(ip, prefix)),
        Some(ReservedAddress::Broadcast) => Err(Ipv4InterfaceError::IsBroadcastAddress(ip, prefix)),
        None => Ok(Ipv4Interface { addr: ip, prefix }),
    }
}

#[derive(Debug)]
pub enum Ipv4InterfaceError {
    ParseCidrError(ParseCidrError),
    IsNetworkAddress(Ipv4Addr, u8),
    IsBroadcastAddress(Ipv4Addr, u8),
}

impl Display for Ipv4InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseCidrError(error) => error.fmt(f),
            Self::IsNetworkAddress(ip, prefix) => {
                fmt_cidr(ip, *prefix, f)?;
                write!(f, " is a network address, expected host address")
            }
            Self::IsBroadcastAddress(ip, prefix) => {
                fmt_cidr(ip, *prefix, f)?;
                write!(f, " is a broadcast address, expected host address")
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

    pub fn is_in_same_network(&self, ip: Ipv4Addr) -> bool {
        let mask = self.mask();

        (ip.to_bits() & mask) == (self.addr.to_bits() & mask)
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

/// The two addresses of a subnet that can't belong to a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedAddress {
    Network,
    Broadcast,
}

impl Display for ReservedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::Broadcast => write!(f, "broadcast"),
        }
    }
}

/// Why an IP can't be a host on a subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAHost {
    Outside,
    Reserved(ReservedAddress),
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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

    /// The last address of the subnet.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.addr.to_bits() | !self.mask())
    }

    /// Whether `ip` is this subnet's network or broadcast address, which can't be
    /// assigned to a host. A /31 (RFC 3021 point-to-point) and a /32 have no such
    /// addresses: every address in them is a host.
    pub fn reserved_address(&self, ip: Ipv4Addr) -> Option<ReservedAddress> {
        if self.prefix > 30 {
            None
        } else if ip == self.addr {
            Some(ReservedAddress::Network)
        } else if ip == self.broadcast() {
            Some(ReservedAddress::Broadcast)
        } else {
            None
        }
    }

    /// `ip` as a host on this subnet: inside it, and neither its network nor its
    /// broadcast address.
    pub fn host_interface(&self, ip: Ipv4Addr) -> Result<Ipv4Interface, NotAHost> {
        if !self.contains(ip) {
            Err(NotAHost::Outside)
        } else if let Some(kind) = self.reserved_address(ip) {
            Err(NotAHost::Reserved(kind))
        } else {
            Ok(Ipv4Interface {
                addr: ip,
                prefix: self.prefix,
            })
        }
    }

    /// Whether `network` lies entirely inside this subnet.
    pub fn contains_network(&self, network: Ipv4Network) -> bool {
        self.prefix <= network.prefix && self.contains(network.addr)
    }

    pub fn overlap(&self, network: Ipv4Network) -> bool {
        if self.prefix <= network.prefix {
            self.contains(network.addr)
        } else {
            network.contains(self.addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> Ipv4Network {
        s.parse().unwrap()
    }

    #[test]
    fn network_valid() {
        let n = net("10.0.0.0/24");
        assert_eq!(n.ip(), ip("10.0.0.0"));
        assert_eq!(n.prefix(), 24);
        assert_eq!(n.to_string(), "10.0.0.0/24");
        // /32 and /0 are valid network addresses
        assert!("1.2.3.4/32".parse::<Ipv4Network>().is_ok());
        assert!("0.0.0.0/0".parse::<Ipv4Network>().is_ok());
    }

    #[test]
    fn network_rejects_host_bits_set() {
        assert!(matches!(
            "10.0.0.5/24".parse::<Ipv4Network>(),
            Err(Ipv4NetworkError::NotANetworkAddress(..))
        ));
    }

    #[test]
    fn network_parse_errors() {
        assert!(matches!(
            "10.0.0.0".parse::<Ipv4Network>(),
            Err(Ipv4NetworkError::ParseCidrError(ParseCidrError::NoPrefix(
                _
            )))
        ));
        assert!(matches!(
            "10.0.0.0/33".parse::<Ipv4Network>(),
            Err(Ipv4NetworkError::ParseCidrError(
                ParseCidrError::InvalidPrefix(_)
            ))
        ));
    }

    #[test]
    fn network_contains() {
        let n = net("10.0.0.0/24");
        assert!(n.contains(ip("10.0.0.0")));
        assert!(n.contains(ip("10.0.0.255")));
        assert!(!n.contains(ip("10.0.1.0")));
    }

    #[test]
    fn network_overlap() {
        assert!(net("10.0.0.0/24").overlap(net("10.0.0.0/24"))); // equal
        assert!(!net("10.0.0.0/24").overlap(net("10.0.1.0/24"))); // disjoint/adjacent
        // nested overlaps both directions
        assert!(net("10.0.0.0/16").overlap(net("10.0.5.0/24")));
        assert!(net("10.0.5.0/24").overlap(net("10.0.0.0/16")));
    }

    #[test]
    fn network_contains_network() {
        assert!(net("10.0.0.0/16").contains_network(net("10.0.5.0/24")));
        assert!(net("10.0.0.0/24").contains_network(net("10.0.0.0/24"))); // equal
        // overlapping, but the other way round: the bigger one isn't inside,
        // even when both start at the same address
        assert!(!net("10.0.5.0/24").contains_network(net("10.0.0.0/16")));
        assert!(!net("10.0.0.0/24").contains_network(net("10.0.0.0/16")));
        assert!(!net("10.0.0.0/24").contains_network(net("10.0.1.0/24"))); // disjoint
    }

    #[test]
    fn network_host_is_slash_32() {
        let h = Ipv4Network::host(ip("10.0.0.5"));
        assert_eq!(h.prefix(), 32);
        assert_eq!(h.ip(), ip("10.0.0.5"));
    }

    #[test]
    fn interface_valid_host() {
        let i: Ipv4Interface = "192.168.1.1/24".parse().unwrap();
        assert_eq!(i.ip(), ip("192.168.1.1"));
        assert_eq!(i.prefix(), 24);
        assert_eq!(i.to_string(), "192.168.1.1/24");
    }

    #[test]
    fn interface_rejects_network_address() {
        // a host that is the network address (host bits zero) is rejected when prefix < 32
        assert!(matches!(
            "192.168.1.0/24".parse::<Ipv4Interface>(),
            Err(Ipv4InterfaceError::IsNetworkAddress(..))
        ));
        // but /32 is always a valid host
        assert!("192.168.1.0/32".parse::<Ipv4Interface>().is_ok());
    }

    #[test]
    fn network_broadcast_and_reserved_addresses() {
        let n = net("192.168.1.0/24");
        assert_eq!(n.broadcast(), ip("192.168.1.255"));
        assert_eq!(
            n.reserved_address(ip("192.168.1.0")),
            Some(ReservedAddress::Network)
        );
        assert_eq!(
            n.reserved_address(ip("192.168.1.255")),
            Some(ReservedAddress::Broadcast)
        );
        assert_eq!(n.reserved_address(ip("192.168.1.1")), None);
        assert_eq!(n.reserved_address(ip("192.168.1.254")), None);
        // /31 and /32 have no reserved addresses
        assert_eq!(net("10.0.0.0/31").reserved_address(ip("10.0.0.0")), None);
        assert_eq!(net("10.0.0.0/31").reserved_address(ip("10.0.0.1")), None);
        assert_eq!(net("10.0.0.5/32").reserved_address(ip("10.0.0.5")), None);
    }

    #[test]
    fn interface_rejects_broadcast_address() {
        assert!(matches!(
            "192.168.1.255/24".parse::<Ipv4Interface>(),
            Err(Ipv4InterfaceError::IsBroadcastAddress(..))
        ));
    }

    #[test]
    fn interface_slash_31_both_addresses_valid() {
        // RFC 3021 point-to-point: no network/broadcast address in a /31.
        assert!("10.0.0.0/31".parse::<Ipv4Interface>().is_ok());
        assert!("10.0.0.1/31".parse::<Ipv4Interface>().is_ok());
    }

    #[test]
    fn interface_network_masks_host_bits() {
        let i: Ipv4Interface = "192.168.1.5/24".parse().unwrap();
        assert_eq!(i.network(), net("192.168.1.0/24"));
    }

    #[test]
    fn interface_is_in_same_network() {
        let i: Ipv4Interface = "192.168.1.1/24".parse().unwrap();
        assert!(i.is_in_same_network(ip("192.168.1.50")));
        assert!(!i.is_in_same_network(ip("192.168.2.1")));
    }

    #[test]
    fn network_host_interface_takes_the_subnet_prefix() {
        let n = net("192.168.1.0/24");
        assert_eq!(
            n.host_interface(ip("192.168.1.50")).unwrap().to_string(),
            "192.168.1.50/24"
        );
        // A /32 has no reserved addresses: its one address is a host.
        assert_eq!(
            net("10.0.0.5/32")
                .host_interface(ip("10.0.0.5"))
                .unwrap()
                .to_string(),
            "10.0.0.5/32"
        );
    }

    #[test]
    fn network_host_interface_rejects_what_cant_be_a_host() {
        let n = net("192.168.1.0/24");
        assert_eq!(n.host_interface(ip("192.168.2.50")), Err(NotAHost::Outside));
        assert_eq!(
            n.host_interface(ip("192.168.1.0")),
            Err(NotAHost::Reserved(ReservedAddress::Network))
        );
        assert_eq!(
            n.host_interface(ip("192.168.1.255")),
            Err(NotAHost::Reserved(ReservedAddress::Broadcast))
        );
    }
}
