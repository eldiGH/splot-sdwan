//! Linux: the rendered files made live through systemd. Only the WireGuard so
//! far, with wg-quick.

mod apply;
mod file;
pub(crate) mod key_store;

use splot_core::protocol::{
    Run,
    linux::{Rendered, WgQuickConfig},
};

use crate::{
    key_store::KeyStore,
    node,
    secret::{self, MissingPsks},
};
pub use apply::{Error, Prepared};
use key_store::FileKeyStore;

/// The mesh interface: the name it has on OpenWrt too.
const INTERFACE: &str = "spl_mesh";

/// The file with the secrets from `store`: what apply writes. Refuses when a
/// pair's preshared key isn't stored.
fn filled(config: &WgQuickConfig, store: &impl KeyStore) -> Result<String, MissingPsks> {
    Ok(config.text(secret::values(config.secrets(), store)?))
}

/// The wg-quick file with its secrets in, once this peer is checked to be the
/// node `rendered` is for; none where splot leaves the WireGuard alone.
fn confirmed(rendered: &Rendered) -> Result<Option<(&WgQuickConfig, String)>, Error> {
    let store = rendered
        .wireguard
        .is_some()
        .then(FileKeyStore::load)
        .transpose()
        .map_err(node::NotConfirmed::KeyStore)?;
    let store = node::confirm_node(
        &rendered.node,
        &rendered.public_key,
        rendered.wireguard.is_some(),
        store.as_ref(),
    )?;

    // There's a store exactly where splot runs the WireGuard.
    match (&rendered.wireguard, store) {
        (Some(config), Some(store)) => Ok(Some((config, filled(config, store)?))),
        _ => Ok(None),
    }
}

/// What `apply` would change on this peer, as the dry run shows it, changing
/// nothing.
pub fn dry_run(rendered: &Rendered) -> Result<String, Error> {
    match confirmed(rendered)? {
        Some((config, text)) => apply::print(config, &text),
        None => Ok("# Nothing to change.\n".to_owned()),
    }
}

/// Begins `run` to make `rendered` live on this peer, changing nothing yet.
pub fn prepare(rendered: &Rendered, run: &Run) -> Result<Prepared, Error> {
    match confirmed(rendered)? {
        Some((config, text)) => apply::prepare(config, &text, run),
        None => {
            crate::run::begin(run, None)?;
            Ok(Prepared::nothing())
        }
    }
}

/// Makes what run `id` prepared live. Returns what changed.
pub fn go(prepared: &Prepared, id: &str) -> Result<Vec<String>, Error> {
    apply::go(prepared, id)
}

/// Puts back the wg-quick file a run changed (see `apply::restore`).
pub(crate) fn restore(file: Option<&str>, active: bool, enabled: bool) -> Result<(), Error> {
    apply::restore(file, active, enabled)
}

#[cfg(test)]
mod tests {
    use splot_core::{host::HostRef, protocol::linux::Line, secret::Secret};

    use super::*;

    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSA=";
    const LAKE_PSK: &str = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTA=";
    const PHONE_PSK: &str = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUA=";

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn lake() -> HostRef {
        HostRef::Node("Lake".parse().unwrap())
    }

    fn phone() -> HostRef {
        HostRef::Client("Phone".parse().unwrap())
    }

    /// Home's file: its private key, then Cabin, Lake and Phone with a PSK, and
    /// the camera on its hub without one.
    fn home() -> WgQuickConfig {
        let text = |line: &str| Line::Text(line.to_owned());
        let psk = |peer: HostRef| Line::Secret {
            key: "PresharedKey".to_owned(),
            secret: Secret::Psk(peer),
        };
        let peer = |name: &str, key: char| {
            vec![
                text(""),
                text(&format!("# {name}")),
                text("[Peer]"),
                text(&format!("PublicKey = {}A=", key.to_string().repeat(42))),
            ]
        };

        let mut lines = vec![
            text("[Interface]"),
            text("Address = 10.100.0.1/16"),
            Line::Secret {
                key: "PrivateKey".to_owned(),
                secret: Secret::PrivateKey,
            },
        ];
        for (name, key, host) in [
            ("Cabin", 'C', cabin()),
            ("Lake", 'D', lake()),
            ("Phone", 'E', phone()),
        ] {
            lines.extend(peer(name, key));
            lines.push(psk(host));
        }
        lines.extend(peer("Home.camera", 'B'));

        WgQuickConfig {
            lines,
            address: "10.100.0.1/16".to_owned(),
            routes: Default::default(),
        }
    }

    #[test]
    fn apply_fills_in_the_secrets_and_the_rendered_file_holds_none() {
        let config = home();
        let store = FileKeyStore::for_tests(PRIVATE_KEY)
            .with_psk(&cabin(), CABIN_PSK)
            .with_psk(&lake(), LAKE_PSK)
            .with_psk(&phone(), PHONE_PSK);
        let filled = filled(&config, &store).unwrap();

        assert!(filled.contains(&format!("\nPrivateKey = {PRIVATE_KEY}\n")));
        for psk in [CABIN_PSK, LAKE_PSK, PHONE_PSK] {
            assert_eq!(filled.matches(psk).count(), 1, "{psk}");
        }
        // Each in its peer's section.
        assert!(filled.contains(&format!(
            "# Lake\n[Peer]\nPublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=\nPresharedKey = {LAKE_PSK}\n"
        )));
        // Nothing else moved: the filled file is the masked one with the secrets in.
        let masked = config.masked();
        assert_eq!(filled.lines().count(), masked.lines().count());
        assert!(!filled.contains('<'));

        for secret in [PRIVATE_KEY, CABIN_PSK, LAKE_PSK, PHONE_PSK] {
            assert!(!masked.contains(secret));
        }
    }

    #[test]
    fn apply_refuses_while_a_pairs_psk_is_missing() {
        let store = FileKeyStore::for_tests(PRIVATE_KEY).with_psk(&lake(), LAKE_PSK);
        let MissingPsks(missing) = filled(&home(), &store).unwrap_err();
        assert_eq!(missing, ["Cabin", "Phone"]);
    }
}
