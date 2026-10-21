//! splot's agent: everything splot does on a node. splot validates the config,
//! plans each node and renders what it should hold; the agent, on the node,
//! checks it's the node the config is for, fills the secrets in from the
//! node's key store, and makes the node hold it. No secret leaves the node.

mod env;
mod key_store;
mod linux;
mod node;
pub mod openwrt;
mod process;
mod secret;
#[cfg(test)]
mod test_support;
mod wg;

use splot_core::{
    host::HostRef,
    identifier::Identifier,
    os::Os,
    protocol::{Failure, Rendered, Reply, Request},
    wg_key::{WgPresharedKey, WgPublicKey},
};

use key_store::{KeyStore, KeyStoreError};
use linux::key_store::FileKeyStore;
use openwrt::key_store::UciKeyStore;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Does what `request` asks, on this peer.
pub fn handle(request: Request) -> Reply {
    let result = match request {
        Request::Os => Ok(Reply::Os(node::detect_os())),
        Request::Init { os } => init(os),
        Request::StorePsk {
            node,
            public_key,
            os,
            peer,
            key,
        } => store_psk(&node, &public_key, os, &peer, &key),
        Request::Apply { rendered, dry_run } => apply(&rendered, dry_run),
    };

    result.unwrap_or_else(|error| Reply::Failed(Failure::of(error.as_ref())))
}

/// Gives this peer its WireGuard key in the key store of `os`, unless it has
/// one: a key is never replaced.
fn init(os: Os) -> Result<Reply, Error> {
    match os {
        Os::OpenWrt => init_with::<UciKeyStore>(),
        Os::Linux => init_with::<FileKeyStore>(),
    }
}

fn init_with<S: KeyStore>() -> Result<Reply, Error> {
    let (store, created) = match S::load() {
        Ok(store) => (store, false),
        Err(KeyStoreError::NotInitialised) => {
            S::create_private_key()?;
            (S::load()?, true)
        }
        Err(err) => return Err(err.into()),
    };
    let public_key = wg::get_pubkey(store.private_key()).map_err(KeyStoreError::Wg)?;

    Ok(Reply::Initialised {
        public_key,
        created,
    })
}

/// Stores `key` as the preshared key of the pair of `node` with `peer`, once
/// it's checked this peer runs `os` and is `node`, whose key the config has as
/// `public_key`.
fn store_psk(
    node: &Identifier,
    public_key: &WgPublicKey,
    os: Os,
    peer: &HostRef,
    key: &WgPresharedKey,
) -> Result<Reply, Error> {
    node::check_os(node, os)?;

    match os {
        Os::OpenWrt => store_psk_with::<UciKeyStore>(node, public_key, peer, key)?,
        Os::Linux => store_psk_with::<FileKeyStore>(node, public_key, peer, key)?,
    }

    Ok(Reply::Stored)
}

fn store_psk_with<S: KeyStore>(
    node: &Identifier,
    public_key: &WgPublicKey,
    peer: &HostRef,
    key: &WgPresharedKey,
) -> Result<(), KeyStoreError> {
    S::load()?.check_node(node, public_key)?;
    S::store_psk(peer, key)
}

/// Makes this peer hold `rendered`, or (`dry_run`) says what that would change,
/// once it's checked this peer runs the OS `rendered` is for.
fn apply(rendered: &Rendered, dry_run: bool) -> Result<Reply, Error> {
    let (node, os) = match rendered {
        Rendered::OpenWrt(rendered) => (&rendered.node, Os::OpenWrt),
        Rendered::Linux(rendered) => (&rendered.node, Os::Linux),
    };
    node::check_os(node, os)?;

    Ok(match (rendered, dry_run) {
        (Rendered::OpenWrt(rendered), true) => Reply::DryRun(openwrt::dry_run(rendered)?),
        (Rendered::OpenWrt(rendered), false) => Reply::Applied(openwrt::apply(rendered)?),
        (Rendered::Linux(rendered), true) => Reply::DryRun(linux::dry_run(rendered)?),
        (Rendered::Linux(rendered), false) => Reply::Applied(linux::apply(rendered)?),
    })
}

#[cfg(test)]
mod tests {
    use splot_core::protocol::{linux, openwrt};

    use super::*;

    #[test]
    fn every_error_is_a_std_error() {
        // Fails to compile, not to run, when one isn't: an error crosses to
        // splot as its message and its causes'.
        fn is_error<E: std::error::Error + Send + Sync + 'static>() {}

        is_error::<process::Error>();
        is_error::<wg::Error>();
        is_error::<KeyStoreError>();
        is_error::<node::NotConfirmed>();
        is_error::<node::WrongOs>();
        is_error::<secret::MissingPsks>();
        is_error::<crate::openwrt::Error>();
        is_error::<crate::linux::Error>();
    }

    #[test]
    fn a_config_for_another_os_than_this_peers_is_refused_before_anything_else() {
        // Where the tests run, the OS splot detects; the config says the other.
        let Some(found) = node::detect_os() else {
            return;
        };
        let (node, public_key) = (
            "Home".parse().unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
        );
        let rendered = match found {
            Os::Linux => Rendered::OpenWrt(openwrt::Rendered {
                node,
                public_key,
                wireguard: true,
                files: Vec::new(),
                secrets: Vec::new(),
            }),
            Os::OpenWrt => Rendered::Linux(linux::Rendered {
                node,
                public_key,
                wireguard: None,
            }),
        };
        let os = match found {
            Os::Linux => Os::OpenWrt,
            Os::OpenWrt => Os::Linux,
        };

        for dry_run in [true, false] {
            let reply = handle(Request::Apply {
                rendered: rendered.clone(),
                dry_run,
            });
            assert_eq!(
                reply,
                Reply::Failed(Failure(vec![format!(
                    "this peer runs {found}, but the config says Home runs {os}"
                )]))
            );
        }
    }
}
