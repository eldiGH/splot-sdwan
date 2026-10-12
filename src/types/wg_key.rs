//! WireGuard key format: 32 bytes, base64-encoded with padding. That is always
//! 44 characters: 43 base64 characters followed by a single `=`.

use std::{fmt, str::FromStr};

use serde::Deserialize;

const KEY_LEN: usize = 44;

/// 32 bytes are 256 bits; 43 base64 characters carry 258. So the last data
/// character (the one before `=`) holds only 4 key bits, and its 2 low bits must
/// be zero. Only these 16 characters qualify; any other is not canonical base64,
/// and `wg` rejects the key.
const LAST_DATA_CHARS: &[u8] = b"AEIMQUYcgkosw048";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyFormatError {
    #[error("key is empty")]
    Empty,
    #[error("key must be 44 characters (32 bytes in base64), got {0}")]
    InvalidLen(usize),
    #[error("key must end with '=' padding")]
    MissingPadding,
    #[error("key contains a character that isn't base64")]
    InvalidChars,
    #[error(
        "key isn't base64 of exactly 32 bytes: the character before '=' must be one of AEIMQUYcgkosw048"
    )]
    NonCanonical,
}

/// Checks that `key` is a well-formed WireGuard key (private or public — the
/// format is the same).
pub fn check_key_format(key: &str) -> Result<(), KeyFormatError> {
    let bytes = key.as_bytes();

    if bytes.is_empty() {
        return Err(KeyFormatError::Empty);
    }

    if bytes.len() != KEY_LEN {
        return Err(KeyFormatError::InvalidLen(key.chars().count()));
    }

    if bytes[KEY_LEN - 1] != b'=' {
        return Err(KeyFormatError::MissingPadding);
    }

    let data = &bytes[..KEY_LEN - 1];
    if !data
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    {
        return Err(KeyFormatError::InvalidChars);
    }

    if !LAST_DATA_CHARS.contains(&data[KEY_LEN - 2]) {
        return Err(KeyFormatError::NonCanonical);
    }

    Ok(())
}

/// A WireGuard public key, validated on parse. Being plain base64 it is also safe
/// to place inside quotes in generated config.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct WgPublicKey(String);

impl WgPublicKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for WgPublicKey {
    type Err = KeyFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        check_key_format(s)?;
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for WgPublicKey {
    type Error = KeyFormatError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        check_key_format(&value)?;
        Ok(Self(value))
    }
}

impl fmt::Display for WgPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<WgPublicKey, KeyFormatError> {
        s.parse()
    }

    // A real-looking key: 43 base64 chars ending in a canonical '0', then '='.
    const VALID: &str = "abcDEF0123456789+/abcDEF0123456789+/abcDEF0=";

    #[test]
    fn valid_key_round_trips() {
        let key = parse(VALID).unwrap();
        assert_eq!(key.as_str(), VALID);
        assert_eq!(key.to_string(), VALID);
    }

    #[test]
    fn every_canonical_last_char_is_accepted() {
        for c in "AEIMQUYcgkosw048".chars() {
            let key = format!("{}{c}=", "A".repeat(42));
            assert!(parse(&key).is_ok(), "{key} should be valid");
        }
    }

    #[test]
    fn empty_is_rejected() {
        assert_eq!(parse(""), Err(KeyFormatError::Empty));
    }

    #[test]
    fn wrong_length_is_rejected_with_the_length() {
        assert_eq!(parse("AAAA"), Err(KeyFormatError::InvalidLen(4)));
        assert_eq!(
            parse(&format!("{VALID}A")),
            Err(KeyFormatError::InvalidLen(45))
        );
    }

    #[test]
    fn missing_padding_is_rejected() {
        assert_eq!(parse(&"A".repeat(44)), Err(KeyFormatError::MissingPadding));
    }

    #[test]
    fn non_base64_character_is_rejected() {
        // Right length and padding; '!' and '-' are not base64. A quote would
        // break out of the quoted value in a generated uci command.
        for bad in ['!', '-', '\'', ' '] {
            let key = format!("{bad}{}=", "A".repeat(42));
            assert_eq!(parse(&key), Err(KeyFormatError::InvalidChars), "{key}");
        }
    }

    #[test]
    fn non_canonical_last_char_is_rejected() {
        // `wg` itself refuses these ("Key is not the correct length or format").
        for c in ['B', 'D', 'Z', 'z', '9', '+', '/'] {
            let key = format!("{}{c}=", "A".repeat(42));
            assert_eq!(parse(&key), Err(KeyFormatError::NonCanonical), "{key}");
        }
    }

    #[test]
    fn deserializes_from_yaml_and_rejects_bad_keys() {
        #[derive(Deserialize)]
        struct Wrapper {
            key: WgPublicKey,
        }
        let ok: Wrapper = serde_norway::from_str(&format!("key: {VALID}")).unwrap();
        assert_eq!(ok.key.as_str(), VALID);
        assert!(serde_norway::from_str::<Wrapper>("key: AAAA").is_err());
    }
}
