//! Linux: the rendered files made live through systemd: the WireGuard with
//! wg-quick, the firewall as splot's own nft table, the DHCP with the
//! operator's dnsmasq reading splot's file.

mod apply;
mod dnsmasq;
mod file;
pub(crate) mod key_store;
mod nftables;

use splot_core::protocol::{
    Changes, Run,
    linux::{Rendered, WgQuickConfig},
};

use crate::{
    key_store::KeyStore,
    node,
    run::{self, Backup},
    secret::{self, MissingPsks},
};
pub use apply::{Error, Kept as WgQuickKept};
pub use dnsmasq::Kept as DnsmasqKept;
use key_store::FileKeyStore;
pub use nftables::Kept as NftablesKept;

/// The mesh interface: the name it has on OpenWrt too.
const INTERFACE: &str = splot_core::consts::MESH_DEVICE;

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

/// The changes of each concern as one: their summaries, then their texts, in
/// turn.
fn joined(changes: impl IntoIterator<Item = Changes>) -> Changes {
    let changes: Vec<Changes> = changes
        .into_iter()
        .filter(|changes| !changes.is_empty())
        .collect();
    if changes.is_empty() {
        return Changes::none();
    }

    Changes {
        summary: changes
            .iter()
            .flat_map(|changes| changes.summary.iter().cloned())
            .collect(),
        text: changes
            .iter()
            .map(|changes| changes.text.as_str())
            .collect(),
    }
}

/// What `apply` would change on this peer, as the dry run shows it, and what
/// of the peer's own firewall decides some of what splot does; changing
/// nothing.
pub fn dry_run(rendered: &Rendered) -> Result<(Changes, Vec<String>), Error> {
    let wireguard = confirmed(rendered)?;

    let mut changes = Vec::new();
    let mut warnings = Vec::new();
    if let Some(text) = &rendered.firewall {
        changes.push(nftables::print(text)?);
        warnings = nftables::warnings()?;
    }
    if let Some((config, text)) = wireguard {
        changes.push(apply::print(config, &text)?);
    }
    if let Some(text) = &rendered.dhcp {
        changes.push(dnsmasq::print(text)?);
        warnings.extend(dnsmasq::warnings());
    }

    Ok((joined(changes), warnings))
}

/// What a run prepared on this peer: each concern's change, none where nothing
/// changes.
pub struct Prepared {
    firewall: Option<nftables::Prepared>,
    wireguard: Option<apply::Prepared>,
    dhcp: Option<dnsmasq::Prepared>,
    changes: Changes,
}

impl Prepared {
    /// Nothing to do.
    #[cfg(test)]
    pub(crate) fn nothing() -> Self {
        Self {
            firewall: None,
            wireguard: None,
            dhcp: None,
            changes: Changes::none(),
        }
    }

    /// What the go changes, as the dry run shows it.
    pub fn changes(&self) -> &Changes {
        &self.changes
    }
}

/// Begins `run` to make `rendered` live on this peer, changing nothing yet:
/// works out what each concern changes, and keeps what the node has of it for
/// the run.
pub fn prepare(rendered: &Rendered, run: &Run) -> Result<Prepared, Error> {
    let wireguard = match confirmed(rendered)? {
        Some((config, text)) => apply::prepare(config, &text)?,
        None => None,
    };
    let firewall = match &rendered.firewall {
        Some(text) => nftables::prepare(text)?,
        None => None,
    };
    let dhcp = match &rendered.dhcp {
        Some(text) => dnsmasq::prepare(text)?,
        None => None,
    };

    let backup =
        (firewall.is_some() || wireguard.is_some() || dhcp.is_some()).then(|| Backup::Linux {
            firewall: firewall.as_ref().map(|prepared| prepared.kept.clone()),
            wireguard: wireguard.as_ref().map(|prepared| prepared.kept.clone()),
            dhcp: dhcp.as_ref().map(|prepared| prepared.kept.clone()),
        });
    run::begin(run, INTERFACE, backup)?;

    let changes = joined(
        [
            firewall.as_ref().map(|prepared| prepared.changes.clone()),
            wireguard.as_ref().map(|prepared| prepared.changes.clone()),
            dhcp.as_ref().map(|prepared| prepared.changes.clone()),
        ]
        .into_iter()
        .flatten(),
    );
    Ok(Prepared {
        firewall,
        wireguard,
        dhcp,
        changes,
    })
}

/// Makes what run `id` prepared live: the firewall first, so the mesh comes up,
/// or changes, behind the rules meant for it; the DHCP last, once the mesh it
/// routes to is there. When any of it fails, puts back what the node had.
/// Returns what changed.
pub fn go(prepared: &Prepared, id: &str) -> Result<Vec<String>, Error> {
    run::go(id)?;

    let applied = (|| {
        if let Some(firewall) = &prepared.firewall {
            nftables::go(firewall)?;
        }
        if let Some(wireguard) = &prepared.wireguard {
            apply::go(wireguard)?;
        }
        if let Some(dhcp) = &prepared.dhcp {
            dnsmasq::go(dhcp)?;
        }
        Ok(())
    })();
    if let Err(cause) = applied {
        let cause = Box::new(cause);
        return Err(match run::rollback(id) {
            Ok(()) => Error::PutBack(cause),
            Err(rollback) => Error::NotPutBack { cause, rollback },
        });
    }

    Ok(prepared.changes.summary.clone())
}

/// Puts back what a run changed, each concern it kept, the reverse of the go:
/// the DHCP, the WireGuard, then the firewall. Each is put back even when one
/// before it fails to be.
pub(crate) fn restore(
    firewall: Option<&NftablesKept>,
    wireguard: Option<&WgQuickKept>,
    dhcp: Option<&DnsmasqKept>,
) -> Result<(), Error> {
    let dhcp = dhcp.map_or(Ok(()), dnsmasq::restore);
    let wireguard = wireguard.map_or(Ok(()), apply::restore);
    let firewall = firewall.map_or(Ok(()), nftables::restore);

    dhcp.and(wireguard).and(firewall)
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

    #[test]
    fn each_concerns_changes_are_shown_in_turn_as_one() {
        let changes = |summary: &[&str], text: &str| Changes {
            summary: summary.iter().map(|line| line.to_string()).collect(),
            text: text.to_owned(),
        };
        let firewall = changes(
            &["/etc/splot/firewall.nft", "splot-firewall reloaded"],
            "# the firewall\n",
        );
        let wireguard = changes(&["/etc/wireguard/spl_mesh.conf"], "# the WireGuard\n");

        assert_eq!(
            joined([firewall.clone(), Changes::none(), wireguard.clone()]),
            changes(
                &[
                    "/etc/splot/firewall.nft",
                    "splot-firewall reloaded",
                    "/etc/wireguard/spl_mesh.conf"
                ],
                "# the firewall\n# the WireGuard\n"
            )
        );
        // One alone is as it is; none is nothing to change.
        assert_eq!(joined([Changes::none(), wireguard.clone()]), wireguard);
        assert_eq!(joined([Changes::none(), Changes::none()]), Changes::none());
        assert_eq!(joined([]), Changes::none());
    }
}
