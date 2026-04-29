use std::{fmt::Display, str::FromStr};

use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
pub struct MacAddress([u8; 6]);

#[derive(Debug)]
pub enum ParseMacError {
    InvalidDigit(u8),
    InvalidLen { got: usize },
    InvalidDelimiter(u8),
    InconsistentDelimiter { expected: u8, got: u8 },
}

impl Display for ParseMacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDelimiter(c) => {
                write!(
                    f,
                    "unexpected delimiter '{}', should be either ':' or '-'",
                    *c as char
                )
            }
            Self::InvalidDigit(c) => write!(f, "invalid hex digit '{}'", *c as char),
            Self::InconsistentDelimiter { expected, got } => write!(
                f,
                "mixed delimiters: started with '{}' found '{}'",
                *expected as char, *got as char
            ),
            Self::InvalidLen { got } => write!(f, "expected {MAC_LEN} characters, got {got}"),
        }
    }
}

const MAC_LEN: usize = 17;

fn parse_nibble(byte: u8) -> Result<u8, ParseMacError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ParseMacError::InvalidDigit(byte)),
    }
}

fn check_delimiter(byte: u8, delimiter: &mut Option<u8>) -> Result<(), ParseMacError> {
    match delimiter {
        None => {
            if byte != b':' && byte != b'-' {
                return Err(ParseMacError::InvalidDelimiter(byte));
            }

            *delimiter = Some(byte);
            Ok(())
        }
        Some(delimiter) => {
            if byte != *delimiter {
                return Err(ParseMacError::InconsistentDelimiter {
                    expected: *delimiter,
                    got: byte,
                });
            }

            Ok(())
        }
    }
}

impl FromStr for MacAddress {
    type Err = ParseMacError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut delimiter: Option<u8> = None;
        let mut octets: [u8; 6] = [0; 6];

        let bytes = s.as_bytes();

        if bytes.len() != MAC_LEN {
            return Err(ParseMacError::InvalidLen { got: bytes.len() });
        }

        for (i, octet) in octets.iter_mut().enumerate() {
            let off = i * 3;
            *octet = (parse_nibble(bytes[off])? << 4) | parse_nibble(bytes[off + 1])?;

            if i < 5 {
                check_delimiter(bytes[off + 2], &mut delimiter)?;
            }
        }

        Ok(MacAddress(octets))
    }
}

impl TryFrom<String> for MacAddress {
    type Error = ParseMacError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<MacAddress, ParseMacError> {
        s.parse::<MacAddress>()
    }

    #[test]
    fn valid_colon_lowercase() {
        assert_eq!(
            parse("aa:bb:cc:dd:ee:ff").unwrap().0,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn valid_colon_uppercase() {
        assert_eq!(
            parse("AA:BB:CC:DD:EE:FF").unwrap().0,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
    }

    #[test]
    fn valid_dash_separated() {
        assert_eq!(
            parse("aa-bb-cc-dd-ee-ff").unwrap().0,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn boundary_digits() {
        // exercises '9' and 'f' — would have caught the original .. vs ..= bug
        assert_eq!(
            parse("09:9f:f9:ff:00:19").unwrap().0,
            [0x09, 0x9f, 0xf9, 0xff, 0x00, 0x19]
        );
    }

    #[test]
    fn too_short() {
        assert!(matches!(
            parse("aa:bb:cc:dd:ee"),
            Err(ParseMacError::InvalidLen { .. })
        ));
    }

    #[test]
    fn too_long() {
        assert!(matches!(
            parse("aa:bb:cc:dd:ee:ff:00"),
            Err(ParseMacError::InvalidLen { .. })
        ));
    }

    #[test]
    fn invalid_hex_digit() {
        assert!(matches!(
            parse("gg:bb:cc:dd:ee:ff"),
            Err(ParseMacError::InvalidDigit(_))
        ));
    }

    #[test]
    fn inconsistent_delimiters() {
        assert!(matches!(
            parse("aa:bb-cc:dd:ee:ff"),
            Err(ParseMacError::InconsistentDelimiter { .. })
        ));
    }

    #[test]
    fn invalid_delimiter_char() {
        // '|' is 1 byte so length check passes, delimiter check catches it
        assert!(matches!(
            parse("aa|bb|cc|dd|ee|ff"),
            Err(ParseMacError::InvalidDelimiter(_))
        ));
    }

    #[test]
    fn display_zero_padded() {
        // 0x0a must render as "0a", not "a"
        assert_eq!(
            parse("0a:0b:0c:0d:0e:0f").unwrap().to_string(),
            "0a:0b:0c:0d:0e:0f"
        );
    }

    #[test]
    fn display_uppercase_normalizes_to_lowercase() {
        assert_eq!(
            parse("AA:BB:CC:DD:EE:FF").unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn display_dash_normalizes_to_colon() {
        assert_eq!(
            parse("aa-bb-cc-dd-ee-ff").unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn roundtrip() {
        let original = "aa:bb:cc:dd:ee:ff";
        let mac = parse(original).unwrap();
        let displayed = mac.to_string();
        assert_eq!(parse(&displayed).unwrap().0, mac.0);
    }
}
