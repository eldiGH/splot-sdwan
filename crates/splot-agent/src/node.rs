//! Whether this peer is the node a request is for: the OS it runs, and the key
//! it has.

use std::path::Path;

use splot_core::{identifier::Identifier, os::Os, wg_key::WgPublicKey};

use crate::{
    key_store::{KeyStore, KeyStoreError},
    wg,
};

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

/// This peer runs another OS than the config says `node` runs.
#[derive(Debug, thiserror::Error)]
#[error("this peer runs {found}, but the config says {node} runs {os}")]
pub struct WrongOs {
    node: Identifier,
    os: Os,
    found: Os,
}

/// Checks this peer runs `os`, which the config says `node` runs.
pub fn check_os(node: &Identifier, os: Os) -> Result<(), WrongOs> {
    runs(node, os, detect_os())
}

/// Whether a peer that runs `found` runs `os`. One whose OS splot can't tell
/// (not Linux at all) isn't refused: what it's asked to run there fails on its
/// own.
fn runs(node: &Identifier, os: Os, found: Option<Os>) -> Result<(), WrongOs> {
    match found {
        Some(found) if found != os => Err(WrongOs {
            node: node.clone(),
            os,
            found,
        }),
        _ => Ok(()),
    }
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
pub fn confirm_node<'a, S: KeyStore>(
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
    fn a_peer_that_runs_another_os_than_the_config_says_is_refused() {
        let home: Identifier = "Home".parse().unwrap();
        for (os, other) in [(Os::OpenWrt, Os::Linux), (Os::Linux, Os::OpenWrt)] {
            assert!(runs(&home, os, Some(os)).is_ok());
            assert_eq!(
                runs(&home, os, Some(other)).unwrap_err().to_string(),
                format!("this peer runs {other}, but the config says Home runs {os}")
            );
            assert!(runs(&home, os, None).is_ok());
        }
    }

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
