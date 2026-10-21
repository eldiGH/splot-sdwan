//! The secrets a rendered config needs. What's rendered holds a placeholder in
//! each one's place: apply fills the secrets in from the node's key store, and
//! the dry run shows the placeholders. Each backend records where they go.

use super::key_store::KeyStore;
use crate::model::host::HostRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Secret {
    /// The node's private key.
    PrivateKey,
    /// The preshared key of the node's pair with this peer.
    Psk(HostRef),
}

impl Secret {
    /// What the rendered config holds in its place. Not a valid key, so it can't
    /// pass for one.
    pub(super) fn placeholder(&self) -> &'static str {
        match self {
            Self::PrivateKey => "<private key>",
            Self::Psk(_) => "<preshared key>",
        }
    }
}

/// The value of each of `secrets` in `store`, in order. Refuses when a pair's
/// preshared key isn't stored, naming every such peer.
pub(super) fn values<'a, 'b>(
    secrets: impl IntoIterator<Item = &'b Secret>,
    store: &'a impl KeyStore,
) -> Result<Vec<&'a str>, MissingPsks> {
    let mut values = Vec::new();
    let mut missing = Vec::new();

    for secret in secrets {
        match secret {
            Secret::PrivateKey => values.push(store.private_key().expose()),
            Secret::Psk(peer) => match store.psk(peer) {
                Some(key) => values.push(key.expose()),
                None => missing.push(peer.to_string()),
            },
        }
    }

    if missing.is_empty() {
        Ok(values)
    } else {
        Err(MissingPsks(missing))
    }
}

/// The peers whose pair with the node needs a preshared key the node's key
/// store doesn't have.
#[derive(Debug, thiserror::Error)]
#[error(
    "no preshared key stored for {}: every WireGuard pair uses one unless an end sets `psk: false`. Generate one per pair (`wg genpsk`) and store the same key on both ends, here with `splot psk set <peer>`",
    .0.join(", ")
)]
pub struct MissingPsks(pub Vec<String>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backend::openwrt::key_store::UciKeyStore, types::wg_key::check_key_format};

    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn phone() -> HostRef {
        HostRef::Client("Phone".parse().unwrap())
    }

    #[test]
    fn a_placeholder_cant_pass_for_a_key() {
        for secret in [Secret::PrivateKey, Secret::Psk(cabin())] {
            assert!(
                check_key_format(secret.placeholder()).is_err(),
                "{secret:?}"
            );
        }
    }

    #[test]
    fn each_secret_is_its_value_in_the_store_in_order() {
        let store = UciKeyStore::for_tests(PRIVATE_KEY).with_psk(&cabin(), CABIN_PSK);
        let secrets = [Secret::Psk(cabin()), Secret::PrivateKey];

        assert_eq!(values(&secrets, &store).unwrap(), [CABIN_PSK, PRIVATE_KEY]);
    }

    #[test]
    fn a_pairs_psk_the_store_doesnt_have_is_refused_naming_every_such_peer() {
        let store = UciKeyStore::for_tests(PRIVATE_KEY).with_psk(&cabin(), CABIN_PSK);
        let host = |name: &str| HostRef::Local {
            node: "Home".parse().unwrap(),
            name: name.parse().unwrap(),
        };
        let secrets = [
            Secret::PrivateKey,
            Secret::Psk(phone()),
            Secret::Psk(cabin()),
            Secret::Psk(host("camera")),
        ];

        let MissingPsks(missing) = values(&secrets, &store).unwrap_err();
        assert_eq!(missing, ["Phone", "Home.camera"]);
    }
}
