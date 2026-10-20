//! Backends: how a node's plan becomes config on the platform it runs.

pub mod key_store;
pub mod linux;
pub mod openwrt;
mod secret;

use std::path::Path;

use crate::{
    plan::NodePlan,
    types::{identifier::Identifier, platform::Os, wg_key::WgPublicKey},
    wg,
};
use key_store::{KeyStore, KeyStoreError};

/// The file every OpenWrt has, saying which release it is.
const OPENWRT_RELEASE: &str = "/etc/openwrt_release";

/// The OS this peer runs, as far as splot can tell: OpenWrt by its release
/// file, any other Linux as Linux. None for anything else.
pub fn detect_os() -> Option<Os> {
    if Path::new(OPENWRT_RELEASE).exists() {
        Some(Os::OpenWrt)
    } else if cfg!(target_os = "linux") {
        Some(Os::Linux)
    } else {
        None
    }
}

/// A platform splot configures a node through.
pub trait Backend {
    /// The plan as this platform's config.
    type Rendered;
    type Error;

    /// The plan as this platform's config: what `apply` writes. Pure, so it can
    /// be tested without the node.
    fn render(&self, plan: &NodePlan) -> Self::Rendered;

    /// Shows what `apply` would change on the node, changing nothing.
    fn dry_run(&self, rendered: &Self::Rendered) -> Result<(), Self::Error>;

    /// Makes the rendered config live on the node. Returns what changed.
    fn apply(&self, rendered: &Self::Rendered) -> Result<Vec<String>, Self::Error>;
}

/// Why this peer isn't known to be the node a config is for.
#[derive(Debug, thiserror::Error)]
pub enum NotConfirmed {
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error("can't read this peer's WireGuard keys")]
    InterfaceKeys(#[source] wg::Error),
    #[error(
        "none of this peer's WireGuard interfaces has the key the config has for {node} - is `--node` wrong, or is its WireGuard down? splot leaves {node}'s WireGuard alone, so that's how it knows the peer is {node}"
    )]
    NotTheNodesInterfaces { node: Identifier },
}

/// Checks this peer is `node`, whose key the config has as `public_key`, before
/// anything acts as it. Where splot runs the node's WireGuard (`wireguard`), by
/// the key in its key store (`store`: none if the peer hasn't been initialised),
/// which is then the store to fill the config's secrets from. Where it doesn't,
/// by the peer's own WireGuard, and there's no store.
fn confirm_node<'a, S: KeyStore>(
    node: &Identifier,
    public_key: &WgPublicKey,
    wireguard: bool,
    store: Option<&'a S>,
) -> Result<Option<&'a S>, NotConfirmed> {
    if !wireguard {
        let keys = wg::interface_public_keys().map_err(NotConfirmed::InterfaceKeys)?;
        is_node_by_its_interfaces(node, public_key, &keys)?;
        return Ok(None);
    }

    let store = store.ok_or(KeyStoreError::NotInitialised)?;
    store.check_node(node, public_key)?;

    Ok(Some(store))
}

/// Checks this peer is `node` by its own WireGuard, which splot leaves alone:
/// one of its interfaces has `expected`, the key the config has for `node`.
fn is_node_by_its_interfaces(
    node: &Identifier,
    expected: &WgPublicKey,
    interface_keys: &[WgPublicKey],
) -> Result<(), NotConfirmed> {
    if interface_keys.contains(expected) {
        Ok(())
    } else {
        Err(NotConfirmed::NotTheNodesInterfaces { node: node.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_whose_wireguard_splot_leaves_alone_is_known_by_its_interfaces() {
        let key =
            |c: char| -> WgPublicKey { format!("{}A=", c.to_string().repeat(42)).parse().unwrap() };
        let home: Identifier = "Home".parse().unwrap();

        assert!(is_node_by_its_interfaces(&home, &key('A'), &[key('B'), key('A')]).is_ok());

        let err = is_node_by_its_interfaces(&home, &key('A'), &[key('B')]).unwrap_err();
        assert!(matches!(&err, NotConfirmed::NotTheNodesInterfaces { node } if *node == home));
        assert_eq!(
            err.to_string(),
            "none of this peer's WireGuard interfaces has the key the config has for Home - is `--node` wrong, or is its WireGuard down? splot leaves Home's WireGuard alone, so that's how it knows the peer is Home"
        );
        // No WireGuard up at all.
        assert!(is_node_by_its_interfaces(&home, &key('A'), &[]).is_err());
    }
}
