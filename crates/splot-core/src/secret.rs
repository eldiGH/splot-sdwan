//! The secrets a rendered config needs: what's rendered holds a placeholder in
//! each one's place, and the node fills the secrets in from its key store.

use crate::host::HostRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    /// The node's private key.
    PrivateKey,
    /// The preshared key of the node's pair with this peer.
    Psk(HostRef),
}

impl Secret {
    /// What the rendered config holds in its place. Not a valid key, so it can't
    /// pass for one.
    pub fn placeholder(&self) -> &'static str {
        match self {
            Self::PrivateKey => "<private key>",
            Self::Psk(_) => "<preshared key>",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg_key::check_key_format;

    #[test]
    fn a_placeholder_cant_pass_for_a_key() {
        let cabin = HostRef::Node("Cabin".parse().unwrap());
        for secret in [Secret::PrivateKey, Secret::Psk(cabin)] {
            assert!(
                check_key_format(secret.placeholder()).is_err(),
                "{secret:?}"
            );
        }
    }
}
