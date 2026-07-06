use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

fn wg() -> Command {
    let mut command = Command::new("wg");
    command
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .stdout(Stdio::piped());

    command
}

pub fn generate_private_key() -> String {
    let output = wg().arg("genkey").output().unwrap();

    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

pub fn get_pubkey(private_key: &str) -> String {
    let mut child = wg().arg("pubkey").stdin(Stdio::piped()).spawn().unwrap();

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(private_key.as_bytes()).unwrap();
    }

    let mut stdout = child.stdout.take().unwrap();

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).unwrap();

    child.wait().unwrap();

    String::from_utf8(buf).unwrap().trim_end().to_owned()
}

#[derive(thiserror::Error, Debug)]
pub enum PrivateKeyValidationError {
    #[error("private key cannot be empty")]
    Empty,
    #[error("private key has invalid length")]
    InvalidLen,
    #[error("private key consists of invalid chars")]
    InvalidChars,
}

pub fn validate_private_key(private_key: &str) -> Result<(), PrivateKeyValidationError> {
    if private_key.is_empty() {
        return Err(PrivateKeyValidationError::Empty);
    }

    let bytes = private_key.as_bytes();

    if bytes.len() != 44 {
        return Err(PrivateKeyValidationError::InvalidLen);
    }

    if bytes[43] != b'='
        || !bytes[..43]
            .iter()
            .all(|char| char.is_ascii_alphanumeric() || *char == b'+' || *char == b'/')
    {
        return Err(PrivateKeyValidationError::InvalidChars);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 43 base64 chars + '=' padding — the shape of a real wg key.
    const VALID_KEY: &str = "abcDEF0123456789+/abcDEF0123456789+/abcDEF0=";

    #[test]
    fn valid_key_passes() {
        assert!(validate_private_key(VALID_KEY).is_ok());
    }

    #[test]
    fn empty_key_rejected() {
        assert!(matches!(
            validate_private_key(""),
            Err(PrivateKeyValidationError::Empty)
        ));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(matches!(
            validate_private_key("tooshort="),
            Err(PrivateKeyValidationError::InvalidLen)
        ));
    }

    #[test]
    fn missing_padding_rejected() {
        // Right length, but no trailing '='.
        let key = "A".repeat(44);
        assert!(matches!(
            validate_private_key(&key),
            Err(PrivateKeyValidationError::InvalidChars)
        ));
    }

    #[test]
    fn invalid_chars_rejected() {
        // Right length and padding, but '!' is not base64.
        let key = format!("{}=", "!".repeat(43));
        assert!(matches!(
            validate_private_key(&key),
            Err(PrivateKeyValidationError::InvalidChars)
        ));
    }
}
