//! Where a node keeps its secrets: its private key, and the preshared key of
//! each of its pairs that has one. Each platform keeps them its own way (uci on
//! OpenWrt, a file on Linux); what uses them doesn't need to know which.

use std::error::Error;

use splot_core::{
    host::HostRef,
    identifier::Identifier,
    wg_key::{KeyFormatError, WgPresharedKey, WgPrivateKey, WgPublicKey},
};

use crate::wg;

/// A node's key store. Only `splot init` creates the private key; apply reads
/// it, and the preshared keys, to fill them into the config it writes.
pub trait KeyStore: Sized {
    /// The peer's key store. Writes nothing: a peer without a private key is
    /// told to run `splot init`.
    fn load() -> Result<Self, KeyStoreError>;

    /// Generates the peer's private key and stores it. Only `splot init` does,
    /// and only when the peer has none: a key is never replaced.
    fn create_private_key() -> Result<(), KeyStoreError>;

    /// Stores `key` as the preshared key of the node's pair with `peer`, in
    /// place of any it had.
    fn store_psk(peer: &HostRef, key: &WgPresharedKey) -> Result<(), KeyStoreError>;

    fn private_key(&self) -> &WgPrivateKey;

    /// The preshared key of the node's pair with `peer`, if one is stored.
    fn psk(&self, peer: &HostRef) -> Option<&WgPresharedKey>;

    /// Checks this peer is `node`: its private key's public half is the key the
    /// config has for `node`. Before anything acts as that node.
    fn check_node(&self, node: &Identifier, expected: &WgPublicKey) -> Result<(), KeyStoreError> {
        is_node(node, expected, wg::get_pubkey(self.private_key())?)
    }
}

/// Whether a peer whose public key is `own` is `node`, whose key the config has
/// as `expected`.
fn is_node(
    node: &Identifier,
    expected: &WgPublicKey,
    own: WgPublicKey,
) -> Result<(), KeyStoreError> {
    if own == *expected {
        Ok(())
    } else {
        Err(KeyStoreError::WrongNode {
            node: node.clone(),
            own,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("this peer has no WireGuard key yet - run `splot init --node <name>` first")]
    NotInitialised,
    #[error(
        "this peer's key isn't the one the config has for {node} - is `--node` wrong? `splot init --node {node}` says whose key it is; if this peer is {node} (reinstalled, or its key rotated), set nodes.{node}.publicKey to {own}"
    )]
    WrongNode { node: Identifier, own: WgPublicKey },
    /// The store itself, at `at`, couldn't be read: the program or the file
    /// behind it failed.
    #[error("can't read the key store ({at})")]
    Read {
        at: String,
        #[source]
        cause: Box<dyn Error + Send + Sync>,
    },
    /// Or couldn't be written, or made private.
    #[error("can't write the key store ({at})")]
    Write {
        at: String,
        #[source]
        cause: Box<dyn Error + Send + Sync>,
    },
    /// A line of the store's file that isn't one splot writes there.
    #[error(
        "{at}: {problem} - it holds `private-key <key>` and `psk <peer> <key>` lines, written by splot"
    )]
    Malformed { at: String, problem: &'static str },
    #[error("the private key stored in {at} is invalid")]
    InvalidPrivateKey {
        at: String,
        #[source]
        cause: KeyFormatError,
    },
    #[error("the preshared key stored in {at} is invalid")]
    InvalidPsk {
        at: String,
        #[source]
        cause: KeyFormatError,
    },
    #[error("failed to generate a WireGuard key or derive its public key")]
    Wg(#[from] wg::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const CABIN_KEY: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
    const CAMERA_KEY: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=";

    #[test]
    fn a_peer_is_the_node_whose_key_it_has() {
        let home: Identifier = "Home".parse().unwrap();
        let key = |key: &str| -> WgPublicKey { key.parse().unwrap() };

        assert!(is_node(&home, &key(CABIN_KEY), key(CABIN_KEY)).is_ok());

        let err = is_node(&home, &key(CABIN_KEY), key(CAMERA_KEY)).unwrap_err();
        assert!(
            matches!(&err, KeyStoreError::WrongNode { node, own } if node == &home && own.as_str() == CAMERA_KEY),
            "{err}"
        );
        // It names the key this peer has, so the config can be fixed.
        assert!(err.to_string().contains(CAMERA_KEY), "{err}");
    }
}
