use std::{fmt, num::ParseIntError, str::FromStr};

use serde::Deserialize;

#[derive(Debug)]
pub enum ParsePortError {
    InvalidFormat(ParseIntError),
    CannotBeZero,
}

impl fmt::Display for ParsePortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(err) => write!(f, "invalid port format: {}", err),
            Self::CannotBeZero => write!(f, "port number cannot be 0"),
        }
    }
}

impl std::error::Error for ParsePortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidFormat(err) => Some(err),
            Self::CannotBeZero => None,
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct Port(u16);

impl FromStr for Port {
    type Err = ParsePortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port: u16 = s.parse().map_err(ParsePortError::InvalidFormat)?;

        if port == 0 {
            return Err(ParsePortError::CannotBeZero);
        }

        Ok(Self(port))
    }
}

impl TryFrom<String> for Port {
    type Error = ParsePortError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Port::from_str(&value)
    }
}

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.0
    }
}

impl Port {
    pub fn value(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
pub enum ParsePortRangeError {
    InvalidPort(ParsePortError),
    InvalidRange,
    NoDelimiter,
}

impl fmt::Display for ParsePortRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort(err) => write!(f, "invalid port: {err}"),
            Self::InvalidRange => write!(f, "range is invalid, it should be {{lower}}-{{higher}}"),
            Self::NoDelimiter => write!(f, "missing '-' in port range"),
        }
    }
}

impl std::error::Error for ParsePortRangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPort(err) => Some(err),
            Self::InvalidRange => None,
            Self::NoDelimiter => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct PortRange {
    from: Port,
    to: Port,
}

impl FromStr for PortRange {
    type Err = ParsePortRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (from, to) = s.split_once('-').ok_or(ParsePortRangeError::NoDelimiter)?;

        let from = Port::from_str(from).map_err(ParsePortRangeError::InvalidPort)?;
        let to = Port::from_str(to).map_err(ParsePortRangeError::InvalidPort)?;

        if from >= to {
            return Err(ParsePortRangeError::InvalidRange);
        }

        Ok(Self { from, to })
    }
}

impl TryFrom<String> for PortRange {
    type Error = ParsePortRangeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl PortRange {
    pub fn width(&self) -> u16 {
        self.to.value() - self.from.value()
    }

    pub fn from(&self) -> Port {
        self.from
    }
    pub fn to(&self) -> Port {
        self.to
    }

    pub fn contains(&self, port: Port) -> bool {
        self.from <= port && self.to >= port
    }

    pub fn overlaps(&self, other: PortRange) -> bool {
        self.from <= other.to && self.to >= other.from
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.from, self.to)
    }
}

#[derive(Debug)]
pub enum ParsePortOrRangeError {
    InvalidPort(ParsePortError),
    InvalidRange(ParsePortRangeError),
}

impl fmt::Display for ParsePortOrRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort(err) => write!(f, "invalid port: {err}"),
            Self::InvalidRange(err) => write!(f, "invalid port range: {err}"),
        }
    }
}

impl std::error::Error for ParsePortOrRangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPort(err) => Some(err),
            Self::InvalidRange(err) => Some(err),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum PortOrRange {
    Single(Port),
    Range(PortRange),
}

impl FromStr for PortOrRange {
    type Err = ParsePortOrRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match PortRange::from_str(s) {
            Ok(range) => Ok(PortOrRange::Range(range)),
            Err(err) => match err {
                ParsePortRangeError::NoDelimiter => Port::from_str(s)
                    .map_err(ParsePortOrRangeError::InvalidPort)
                    .map(PortOrRange::Single),
                err => Err(ParsePortOrRangeError::InvalidRange(err)),
            },
        }
    }
}

impl TryFrom<String> for PortOrRange {
    type Error = ParsePortOrRangeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl fmt::Display for PortOrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range(range) => range.fmt(f),
            Self::Single(port) => port.fmt(f),
        }
    }
}

impl From<Port> for PortOrRange {
    fn from(value: Port) -> Self {
        Self::Single(value)
    }
}

impl From<PortRange> for PortOrRange {
    fn from(value: PortRange) -> Self {
        Self::Range(value)
    }
}

impl PortOrRange {
    pub fn conflicts(&self, other: PortOrRange) -> bool {
        match (self, other) {
            (Self::Single(port), Self::Single(other)) => *port == other,
            (Self::Single(port), Self::Range(others)) => others.contains(*port),
            (Self::Range(range), Self::Single(other)) => range.contains(other),
            (Self::Range(range), Self::Range(others)) => range.overlaps(others),
        }
    }
}

#[derive(Debug)]
pub enum ParseServicePortError {
    InvalidPort(ParsePortError),
    InvalidRange(ParsePortRangeError),
    MismatchedRangeWidths {
        external: PortRange,
        internal: PortRange,
    },
    SingleToRangeTranslation {
        external: Port,
        internal: PortRange,
    },
}

impl From<ParsePortOrRangeError> for ParseServicePortError {
    fn from(value: ParsePortOrRangeError) -> Self {
        match value {
            ParsePortOrRangeError::InvalidPort(err) => Self::InvalidPort(err),
            ParsePortOrRangeError::InvalidRange(err) => Self::InvalidRange(err),
        }
    }
}

impl fmt::Display for ParseServicePortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort(err) => write!(f, "invalid port: {err}"),
            Self::InvalidRange(err) => write!(f, "invalid port range: {err}"),
            Self::MismatchedRangeWidths { external, internal } => {
                write!(
                    f,
                    "both ranges should have same width: {external} and {internal}"
                )
            }
            Self::SingleToRangeTranslation { external, internal } => write!(
                f,
                "invalid translation: should never be port:range ({external}:{internal})"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum ServicePort {
    Same(PortOrRange),
    Translation {
        external: Port,
        internal: Port,
    },
    RangeCollapse {
        external: PortRange,
        internal: Port,
    },
    RangeMap {
        external: PortRange,
        internal: PortRange,
    },
}

impl FromStr for ServicePort {
    type Err = ParseServicePortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let translation = s.split_once(':');

        match translation {
            None => Ok(PortOrRange::from_str(s).map(Self::Same)?),

            Some((external, internal)) => {
                let external = PortOrRange::from_str(external)?;
                let internal = PortOrRange::from_str(internal)?;

                match (external, internal) {
                    (PortOrRange::Single(external), PortOrRange::Single(internal)) => {
                        Ok(Self::Translation { external, internal })
                    }

                    (PortOrRange::Range(external), PortOrRange::Single(internal)) => {
                        Ok(Self::RangeCollapse { external, internal })
                    }

                    (PortOrRange::Range(external), PortOrRange::Range(internal)) => {
                        if external.width() != internal.width() {
                            return Err(ParseServicePortError::MismatchedRangeWidths {
                                external,
                                internal,
                            });
                        }

                        Ok(Self::RangeMap { external, internal })
                    }

                    (PortOrRange::Single(external), PortOrRange::Range(internal)) => {
                        Err(ParseServicePortError::SingleToRangeTranslation { external, internal })
                    }
                }
            }
        }
    }
}

impl TryFrom<String> for ServicePort {
    type Error = ParseServicePortError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl fmt::Display for ServicePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Same(port_or_range) => port_or_range.fmt(f),
            Self::Translation { external, internal } => write!(f, "{external}:{internal}",),
            Self::RangeCollapse { external, internal } => write!(f, "{external}:{internal}",),
            Self::RangeMap { external, internal } => write!(f, "{external}:{internal}"),
        }
    }
}

impl ServicePort {
    pub fn internal(&self) -> PortOrRange {
        match self {
            Self::Same(port_or_range) => *port_or_range,
            Self::Translation {
                external: _,
                internal,
            } => PortOrRange::Single(*internal),
            Self::RangeCollapse {
                external: _,
                internal,
            } => PortOrRange::Single(*internal),
            Self::RangeMap {
                external: _,
                internal,
            } => PortOrRange::Range(*internal),
        }
    }

    pub fn external(&self) -> PortOrRange {
        match self {
            Self::Same(port_or_range) => *port_or_range,
            Self::Translation {
                external,
                internal: _,
            } => PortOrRange::Single(*external),
            Self::RangeCollapse {
                external,
                internal: _,
            } => PortOrRange::Range(*external),
            Self::RangeMap {
                external,
                internal: _,
            } => PortOrRange::Range(*external),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_valid_bounds() {
        assert_eq!("1".parse::<Port>().unwrap().value(), 1);
        assert_eq!("65535".parse::<Port>().unwrap().value(), 65535);
    }

    #[test]
    fn port_zero_rejected() {
        assert!(matches!(
            "0".parse::<Port>(),
            Err(ParsePortError::CannotBeZero)
        ));
    }

    #[test]
    fn port_non_numeric_and_overflow() {
        assert!(matches!(
            "abc".parse::<Port>(),
            Err(ParsePortError::InvalidFormat(_))
        ));
        assert!(matches!(
            "65536".parse::<Port>(),
            Err(ParsePortError::InvalidFormat(_))
        ));
    }

    #[test]
    fn range_valid() {
        let r: PortRange = "22-80".parse().unwrap();
        assert_eq!(r.from().value(), 22);
        assert_eq!(r.to().value(), 80);
        assert_eq!(r.width(), 58);
        assert_eq!(r.to_string(), "22-80");
    }

    #[test]
    fn range_inverted_or_equal_rejected() {
        assert!(matches!(
            "80-22".parse::<PortRange>(),
            Err(ParsePortRangeError::InvalidRange)
        ));
        assert!(matches!(
            "22-22".parse::<PortRange>(),
            Err(ParsePortRangeError::InvalidRange)
        ));
    }

    #[test]
    fn range_delimiter_and_endpoint_errors() {
        assert!(matches!(
            "2280".parse::<PortRange>(),
            Err(ParsePortRangeError::NoDelimiter)
        ));
        assert!(matches!(
            "a-80".parse::<PortRange>(),
            Err(ParsePortRangeError::InvalidPort(_))
        ));
    }

    #[test]
    fn range_contains_and_overlaps() {
        let r: PortRange = "22-80".parse().unwrap();
        let p = |n: &str| n.parse::<Port>().unwrap();
        assert!(r.contains(p("22")) && r.contains(p("80")) && r.contains(p("50")));
        assert!(!r.contains(p("21")) && !r.contains(p("81")));

        let pr = |s: &str| s.parse::<PortRange>().unwrap();
        assert!(r.overlaps(pr("80-100"))); // touching at 80
        assert!(r.overlaps(pr("30-40"))); // nested
        assert!(!r.overlaps(pr("81-100"))); // disjoint
    }

    #[test]
    fn port_or_range_parse_variants() {
        assert!(matches!(
            "22".parse::<PortOrRange>(),
            Ok(PortOrRange::Single(_))
        ));
        assert!(matches!(
            "22-80".parse::<PortOrRange>(),
            Ok(PortOrRange::Range(_))
        ));
    }

    #[test]
    fn conflicts_matrix() {
        let por = |s: &str| s.parse::<PortOrRange>().unwrap();
        // single vs single
        assert!(por("22").conflicts(por("22")));
        assert!(!por("22").conflicts(por("23")));
        // single vs range and range vs single
        assert!(por("50").conflicts(por("22-80")));
        assert!(por("22-80").conflicts(por("50")));
        assert!(!por("90").conflicts(por("22-80")));
        // range vs range
        assert!(por("22-80").conflicts(por("70-100")));
        assert!(!por("22-80").conflicts(por("90-100")));
    }

    #[test]
    fn service_port_same() {
        let sp: ServicePort = "22".parse().unwrap();
        assert!(matches!(sp, ServicePort::Same(_)));
        assert_eq!(sp.internal().to_string(), "22");
        assert_eq!(sp.external().to_string(), "22");
        assert_eq!(sp.to_string(), "22");
    }

    #[test]
    fn service_port_translation() {
        let sp: ServicePort = "8080:80".parse().unwrap();
        assert!(matches!(sp, ServicePort::Translation { .. }));
        assert_eq!(sp.external().to_string(), "8080");
        assert_eq!(sp.internal().to_string(), "80");
        assert_eq!(sp.to_string(), "8080:80");
    }

    #[test]
    fn service_port_range_collapse() {
        let sp: ServicePort = "1000-2000:80".parse().unwrap();
        assert!(matches!(sp, ServicePort::RangeCollapse { .. }));
        assert_eq!(sp.external().to_string(), "1000-2000");
        assert_eq!(sp.internal().to_string(), "80");
    }

    #[test]
    fn service_port_range_map() {
        let sp: ServicePort = "1000-2000:3000-4000".parse().unwrap();
        assert!(matches!(sp, ServicePort::RangeMap { .. }));
        assert_eq!(sp.external().to_string(), "1000-2000");
        assert_eq!(sp.internal().to_string(), "3000-4000");
    }

    #[test]
    fn service_port_errors() {
        assert!(matches!(
            "1000-2000:3000-4500".parse::<ServicePort>(),
            Err(ParseServicePortError::MismatchedRangeWidths { .. })
        ));
        assert!(matches!(
            "80:1000-2000".parse::<ServicePort>(),
            Err(ParseServicePortError::SingleToRangeTranslation { .. })
        ));
    }
}
