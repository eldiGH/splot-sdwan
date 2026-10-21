//! The secrets a rendered config needs. What's rendered holds a placeholder in
//! each one's place: apply fills the secrets in from the node's key store, and
//! the dry run shows the placeholders. Each backend records where they go.

use super::key_store::KeyStore;

pub use splot_core::secret::Secret;

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
    use crate::{backend::openwrt::key_store::UciKeyStore, model::host::HostRef};

    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn phone() -> HostRef {
        HostRef::Client("Phone".parse().unwrap())
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
