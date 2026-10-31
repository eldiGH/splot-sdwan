//! OpenWrt: the rendered uci config staged and committed with uci, and made
//! live by reloading the services.

mod apply;
mod contested;
mod diff;
pub(crate) mod key_store;
mod reload;
mod slot;
mod uci;
mod values;

use std::path::PathBuf;

use splot_core::{
    protocol::{Changes, Run, openwrt::Rendered},
    uci::section::Value,
};

use crate::{key_store::KeyStore, node, secret};
pub use apply::{Error, Prepared, find_duplicate_sections};
use key_store::UciKeyStore;

/// `rendered` with the node's secrets from `store` in their slots. Refuses when
/// a pair's preshared key isn't stored, naming the peers.
fn with_secrets(rendered: &Rendered, store: &UciKeyStore) -> Result<Rendered, Error> {
    let values = secret::values(rendered.secrets.iter().map(|slot| &slot.secret), store)?;
    let mut files = rendered.files.clone();

    for (slot, value) in rendered.secrets.iter().zip(values) {
        let option = files
            .iter_mut()
            .filter(|file| file.name == slot.file)
            .flat_map(|file| file.sections.iter_mut())
            .filter(|section| section.name == slot.section)
            .flat_map(|section| section.options.iter_mut())
            .find(|(option, _)| *option == slot.option);

        if let Some((_, option_value)) = option {
            *option_value = Value::Single(value.to_owned());
        }
    }

    Ok(Rendered {
        files,
        ..rendered.clone()
    })
}

/// `rendered` with its secrets filled in, once this peer is checked to be the
/// node it's for: by the key in the key store where splot runs the node's
/// WireGuard; by the node's own WireGuard where it doesn't (no secrets then).
fn confirmed(rendered: &Rendered) -> Result<Rendered, Error> {
    let store = rendered
        .wireguard
        .then(UciKeyStore::load)
        .transpose()
        .map_err(node::NotConfirmed::KeyStore)?;
    let store = node::confirm_node(
        &rendered.node,
        &rendered.public_key,
        rendered.wireguard,
        store.as_ref(),
    )?;

    match store {
        Some(store) => with_secrets(rendered, store),
        None => Ok(rendered.clone()),
    }
}

/// What `apply` would change on this peer, changing nothing, and a warning
/// for each of the operator's own firewall sections that decides some of what
/// splot owns there.
pub fn dry_run(rendered: &Rendered) -> Result<(Changes, Vec<String>), Error> {
    let rendered = confirmed(rendered)?;
    let warnings = if rendered.owned.is_empty() {
        Vec::new()
    } else {
        let current = apply::current(contested::FIREWALL)?;
        contested::contested(&rendered.node, &current, &rendered.owned)
            .iter()
            .map(ToString::to_string)
            .collect()
    };

    Ok((apply::print(&rendered)?, warnings))
}

/// Begins `run` to make `rendered` live on this peer, changing nothing yet.
pub fn prepare(rendered: &Rendered, run: &Run) -> Result<Prepared, Error> {
    apply::prepare(&confirmed(rendered)?, run)
}

/// Makes what run `id` prepared live. Returns the files that changed.
pub fn go(prepared: &Prepared, id: &str) -> Result<Vec<String>, Error> {
    apply::go(prepared, id)
}

/// Puts back the uci files a run changed (see `apply::restore`).
pub(crate) fn restore(files: &[(PathBuf, Option<String>)]) -> Result<(), Error> {
    apply::restore(files)
}

#[cfg(test)]
fn empty() -> Rendered {
    Rendered {
        node: "Home".parse().unwrap(),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .parse()
            .unwrap(),
        wireguard: true,
        files: Vec::new(),
        secrets: Vec::new(),
        owned: Vec::new(),
        dnsmasq: None,
    }
}

/// File `name` with `sections`, splot owning their types there.
#[cfg(test)]
fn file(
    name: &str,
    sections: Vec<splot_core::uci::section::Section>,
) -> splot_core::protocol::openwrt::File {
    let mut types: Vec<String> = sections
        .iter()
        .map(|section| section.section_type.clone())
        .collect();
    types.dedup();

    splot_core::protocol::openwrt::File {
        name: name.to_owned(),
        types,
        sections,
    }
}

#[cfg(test)]
mod tests {
    use splot_core::{
        host::HostRef,
        secret::Secret,
        uci::{section::Section, slot::Slot},
    };

    use super::*;

    // Fake keys, but well-formed: the key store takes nothing else.
    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
    const PHONE_PSK: &str = "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPA=";

    fn section(name: &str, section_type: &str, options: &[(&str, &str)]) -> Section {
        Section {
            name: name.to_owned(),
            section_type: section_type.to_owned(),
            options: options
                .iter()
                .map(|(option, value)| (option.to_string(), Value::Single(value.to_string())))
                .collect(),
        }
    }

    #[test]
    fn apply_fills_in_the_secrets_in_their_slots_and_nothing_else() {
        // Each lookalike comes before the slot, so a fill-in that skipped one of
        // file, section or option would hit it first.
        let placeholder = Secret::PrivateKey.placeholder();
        let rendered = Rendered {
            files: vec![
                // A section of the same name in another file: no slot.
                file(
                    "dhcp",
                    vec![section("spl_mesh", "host", &[("private_key", placeholder)])],
                ),
                file(
                    "network",
                    vec![
                        // The same option in another section: no slot.
                        section("spl_other", "interface", &[("private_key", placeholder)]),
                        section(
                            "spl_mesh",
                            "interface",
                            &[("proto", "wireguard"), ("private_key", placeholder)],
                        ),
                    ],
                ),
            ],
            secrets: vec![Slot {
                file: "network".to_owned(),
                section: "spl_mesh".to_owned(),
                option: "private_key".to_owned(),
                secret: Secret::PrivateKey,
            }],
            ..empty()
        };

        let filled = with_secrets(&rendered, &UciKeyStore::for_tests(PRIVATE_KEY)).unwrap();

        let commands: Vec<String> = filled
            .files
            .iter()
            .flat_map(|file| {
                file.sections
                    .iter()
                    .flat_map(|section| section.commands(&file.name))
            })
            .map(|command| command.to_string())
            .collect();
        assert_eq!(
            commands,
            [
                "set dhcp.spl_mesh='host'",
                "set dhcp.spl_mesh.private_key='<private key>'",
                "set network.spl_other='interface'",
                "set network.spl_other.private_key='<private key>'",
                "set network.spl_mesh='interface'",
                "set network.spl_mesh.proto='wireguard'",
                &format!("set network.spl_mesh.private_key='{PRIVATE_KEY}'"),
            ]
        );
        assert_eq!(filled.files(), ["dhcp", "network"]);
        assert_eq!(filled.secrets, rendered.secrets);
    }

    /// A peer section with a preshared key placeholder, and its slot.
    fn psk_peer(peer: &HostRef) -> (Section, Slot) {
        let name = format!("spl_wireguard_spl_mesh_{}", peer.name());
        let placeholder = Secret::Psk(peer.clone()).placeholder();
        (
            section(
                &name,
                "wireguard_spl_mesh",
                &[("preshared_key", placeholder)],
            ),
            Slot {
                file: "network".to_owned(),
                section: name,
                option: "preshared_key".to_owned(),
                secret: Secret::Psk(peer.clone()),
            },
        )
    }

    fn cabin() -> HostRef {
        HostRef::Node("Cabin".parse().unwrap())
    }

    fn phone() -> HostRef {
        HostRef::Client("Phone".parse().unwrap())
    }

    fn psk_peers(peers: &[HostRef]) -> Rendered {
        let (sections, secrets) = peers.iter().map(psk_peer).unzip();
        Rendered {
            files: vec![file("network", sections)],
            secrets,
            ..empty()
        }
    }

    #[test]
    fn apply_fills_in_each_pairs_psk_from_the_store() {
        let store = UciKeyStore::for_tests(PRIVATE_KEY)
            .with_psk(&cabin(), CABIN_PSK)
            .with_psk(&phone(), PHONE_PSK);
        let filled = with_secrets(&psk_peers(&[cabin(), phone()]), &store).unwrap();

        let commands: Vec<String> = filled.files[0]
            .sections
            .iter()
            .flat_map(|section| section.commands("network"))
            .map(|command| command.to_string())
            .collect();
        assert_eq!(
            commands,
            [
                "set network.spl_wireguard_spl_mesh_Cabin='wireguard_spl_mesh'",
                &format!("set network.spl_wireguard_spl_mesh_Cabin.preshared_key='{CABIN_PSK}'"),
                "set network.spl_wireguard_spl_mesh_Phone='wireguard_spl_mesh'",
                &format!("set network.spl_wireguard_spl_mesh_Phone.preshared_key='{PHONE_PSK}'"),
            ]
        );
    }

    #[test]
    fn apply_refuses_while_a_pairs_psk_is_missing() {
        let missing =
            |store: &UciKeyStore| match with_secrets(&psk_peers(&[cabin(), phone()]), store) {
                Err(Error::MissingPsks(secret::MissingPsks(peers))) => peers,
                Err(err) => panic!("{err}"),
                Ok(_) => panic!("filled in without every PSK"),
            };

        assert_eq!(
            missing(&UciKeyStore::for_tests(PRIVATE_KEY)),
            ["Cabin", "Phone"]
        );
        assert_eq!(
            missing(&UciKeyStore::for_tests(PRIVATE_KEY).with_psk(&cabin(), CABIN_PSK)),
            ["Phone"]
        );
    }
}
