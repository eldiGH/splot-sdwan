//! OpenWrt: the plan as uci config, staged and committed with uci and made live
//! by reloading the services.

mod apply;
mod dhcp;
mod diff;
mod export;
mod firewall;
pub mod key_store;
mod naming;
mod network;
mod reload;
mod section;
mod slot;
pub mod uci;

use log::info;

use crate::{
    backend::{self, Backend, secret},
    plan::NodePlan,
    types::{identifier::Identifier, wg_key::WgPublicKey},
};
pub use apply::Error;
use key_store::UciKeyStore;
use section::{Section, Value};
use slot::Slot;

/// The node's config as uci sections, file by file, in the order splot commits
/// the files, with placeholders where its secrets go.
#[derive(Clone)]
pub struct Rendered {
    /// The node it's for, and the key the config has for it: the dry run and
    /// apply check this peer is that node before anything else.
    node: Identifier,
    public_key: WgPublicKey,
    /// Whether splot runs the node's WireGuard: then its key store has the key,
    /// and the secrets. Otherwise the node's own WireGuard has the key.
    wireguard: bool,
    files: Vec<(&'static str, Vec<Section>)>,
    /// Where its secrets go: apply fills them in, the dry run masks them again.
    secrets: Vec<Slot>,
}

impl Rendered {
    /// The uci files it writes.
    fn files(&self) -> Vec<&'static str> {
        self.files.iter().map(|(file, _)| *file).collect()
    }

    /// The same config with the node's secrets from `store` in their slots.
    /// Refuses when a pair's preshared key isn't stored, naming the peers.
    fn with_secrets(&self, store: &UciKeyStore) -> Result<Self, Error> {
        let values = secret::values(self.secrets.iter().map(|slot| &slot.secret), store)?;
        let mut files = self.files.clone();

        for (slot, value) in self.secrets.iter().zip(values) {
            let option = files
                .iter_mut()
                .filter(|(file, _)| *file == slot.file)
                .flat_map(|(_, sections)| sections.iter_mut())
                .filter(|section| section.name == slot.section)
                .flat_map(|section| section.options.iter_mut())
                .find(|(option, _)| option == slot.option);

            if let Some((_, option_value)) = option {
                *option_value = Value::Single(value.to_owned());
            }
        }

        Ok(Self {
            files,
            ..self.clone()
        })
    }
}

#[cfg(test)]
impl Rendered {
    /// Nothing rendered, for Home: the rest of the tests' own `Rendered`s.
    fn empty() -> Self {
        Self {
            node: "Home".parse().unwrap(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
            wireguard: true,
            files: Vec::new(),
            secrets: Vec::new(),
        }
    }
}

pub struct OpenWrtBackend {
    /// The node's key store, where splot runs its WireGuard: its key says this
    /// peer is the node, and `apply` fills its secrets into the rendered config.
    /// None where splot leaves the WireGuard alone: it keeps no key there.
    key_store: Option<UciKeyStore>,
}

impl OpenWrtBackend {
    pub fn new(key_store: Option<UciKeyStore>) -> Self {
        Self { key_store }
    }

    /// `rendered` with its secrets filled in, once this peer is checked to be
    /// the node it's for: by the key in the key store where splot runs the
    /// node's WireGuard; by the node's own WireGuard where it doesn't (no
    /// secrets then).
    fn confirmed(&self, rendered: &Rendered) -> Result<Rendered, Error> {
        let store = backend::confirm_node(
            &rendered.node,
            &rendered.public_key,
            rendered.wireguard,
            self.key_store.as_ref(),
        )?;

        match store {
            Some(store) => rendered.with_secrets(store),
            None => Ok(rendered.clone()),
        }
    }
}

impl Backend for OpenWrtBackend {
    type Rendered = Rendered;
    type Error = Error;

    /// Only the files of the concerns splot manages on the node: one it leaves
    /// alone keeps its file as it is, splot's own old sections included.
    fn render(&self, plan: &NodePlan) -> Rendered {
        info!("Rendering the uci config of node '{}'", plan.node);
        let mut files = Vec::new();
        let mut secrets = Vec::new();

        if let Some(wireguard) = &plan.wireguard {
            let (network, slots) = network::render(wireguard);
            files.push((network::FILE, network));
            secrets = slots;
        }
        if let Some(firewall) = &plan.firewall {
            files.push((firewall::FILE, firewall::render(firewall)));
        }
        if let Some(dhcp) = &plan.dhcp {
            files.push((dhcp::FILE, dhcp::render(dhcp)));
        }

        Rendered {
            node: plan.node.clone(),
            public_key: plan.public_key.clone(),
            wireguard: plan.wireguard.is_some(),
            files,
            secrets,
        }
    }

    fn dry_run(&self, rendered: &Rendered) -> Result<(), Error> {
        apply::print(&self.confirmed(rendered)?)
    }

    fn apply(&self, rendered: &Rendered) -> Result<Vec<String>, Error> {
        let changed = apply::run(&self.confirmed(rendered)?)?;

        Ok(changed.into_iter().map(str::to_owned).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;
    use crate::{
        backend::secret::Secret,
        model::{Network, host::HostRef, node::Node},
        plan, test_support,
        types::platform::Os,
    };

    // Fake keys, but well-formed: the key store takes nothing else.
    const PRIVATE_KEY: &str = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=";
    const CABIN_PSK: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
    const PHONE_PSK: &str = "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPA=";

    /// The example config, and its nodes that run OpenWrt: the ones this
    /// backend renders.
    fn example() -> Network {
        test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )))
    }

    fn openwrt_nodes(network: &Network) -> impl Iterator<Item = &Node> {
        network
            .nodes()
            .filter(|node| node.platform().os() == Os::OpenWrt)
    }

    // ── Snapshot of everything generated for the example config ────────────
    //
    // Pins the complete uci output for every node of `splot.example.yml`, so any
    // change to what's planned or how it's rendered shows up as a reviewable diff
    // of the generated router config (`cargo insta review`). It records today's
    // output as-is, known-wrong parts included: a fix shows up as a snapshot diff.
    // Keys are fakes; the delete/commit lines need uci and are not part of it.

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
    fn a_concern_splot_leaves_alone_has_no_file() {
        // Nothing rendered for it means nothing staged, deleted, committed or
        // reloaded there: apply works through the rendered files only.
        let rendered = |platform: &str| {
            let network = test_support::checked(&format!(
                "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
{platform}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
"
            ));
            let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
            OpenWrtBackend::new(Some(UciKeyStore::for_tests(PRIVATE_KEY))).render(&plan)
        };

        let all = rendered("");
        assert_eq!(all.files(), ["network", "firewall", "dhcp"]);
        assert_eq!(all.secrets.len(), 1);
        assert!(all.wireguard);

        let network_only = rendered("      firewall: none\n      dhcp: none");
        assert_eq!(network_only.files(), ["network"]);
        assert_eq!(network_only.secrets.len(), 1);
        assert_eq!(
            rendered("      firewall: none").files(),
            ["network", "dhcp"]
        );
        assert_eq!(
            rendered("      dhcp: none").files(),
            ["network", "firewall"]
        );

        // Without WireGuard, no key to fill in either, and the node's own
        // WireGuard says it's this peer.
        let no_wireguard = rendered("      wireguard: none");
        assert_eq!(no_wireguard.files(), ["firewall", "dhcp"]);
        assert!(no_wireguard.secrets.is_empty());
        assert!(!no_wireguard.wireguard);
        assert_eq!(
            no_wireguard.public_key.as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn apply_fills_in_the_secrets_in_their_slots_and_nothing_else() {
        // Each lookalike comes before the slot, so a fill-in that skipped one of
        // file, section or option would hit it first.
        let placeholder = Secret::PrivateKey.placeholder();
        let rendered = Rendered {
            files: vec![
                (
                    "dhcp",
                    // A section of the same name in another file: no slot.
                    vec![section("spl_mesh", "host", &[("private_key", placeholder)])],
                ),
                (
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
                file: "network",
                section: "spl_mesh".to_owned(),
                option: "private_key",
                secret: Secret::PrivateKey,
            }],
            ..Rendered::empty()
        };

        let filled = rendered
            .with_secrets(&UciKeyStore::for_tests(PRIVATE_KEY))
            .unwrap();

        let commands: Vec<String> = filled
            .files
            .iter()
            .flat_map(|(file, sections)| sections.iter().flat_map(|section| section.commands(file)))
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
                file: "network",
                section: name,
                option: "preshared_key",
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
            files: vec![("network", sections)],
            secrets,
            ..Rendered::empty()
        }
    }

    #[test]
    fn apply_fills_in_each_pairs_psk_from_the_store() {
        let store = UciKeyStore::for_tests(PRIVATE_KEY)
            .with_psk(&cabin(), CABIN_PSK)
            .with_psk(&phone(), PHONE_PSK);
        let filled = psk_peers(&[cabin(), phone()]).with_secrets(&store).unwrap();

        let commands: Vec<String> = filled.files[0]
            .1
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
        let missing = |store: &UciKeyStore| match psk_peers(&[cabin(), phone()]).with_secrets(store)
        {
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

    #[test]
    fn every_slot_holds_its_placeholder_and_every_placeholder_has_a_slot() {
        let network = example();
        let backend = OpenWrtBackend::new(Some(UciKeyStore::for_tests(PRIVATE_KEY)));

        for node in openwrt_nodes(&network) {
            let rendered = backend.render(&plan::plan(&network, node.name()).unwrap());
            assert!(!rendered.secrets.is_empty());

            let mut placeholders = 0;
            for (file, sections) in &rendered.files {
                for section in sections {
                    for (option, value) in &section.options {
                        let slot = rendered.secrets.iter().find(|slot| {
                            slot.file == *file
                                && slot.section == section.name
                                && slot.option == option
                        });
                        let is_placeholder = |value: &str| {
                            rendered
                                .secrets
                                .iter()
                                .any(|slot| slot.secret.placeholder() == value)
                        };
                        match (slot, value) {
                            (Some(slot), Value::Single(value)) => {
                                assert_eq!(value, slot.secret.placeholder());
                                placeholders += 1;
                            }
                            (Some(slot), Value::List(_)) => panic!("{slot:?} is a list"),
                            (None, Value::Single(value)) => {
                                assert!(!is_placeholder(value), "{file}.{}.{option}", section.name)
                            }
                            (None, Value::List(values)) => assert!(
                                !values.iter().any(|value| is_placeholder(value)),
                                "{file}.{}.{option}",
                                section.name
                            ),
                        }
                    }
                }
            }
            assert_eq!(placeholders, rendered.secrets.len(), "{}", node.name());
        }
    }

    /// `sections` the way `uci export` prints them.
    fn exported(sections: &[Section]) -> String {
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        let mut text = String::from("package file\n");

        for section in sections {
            writeln!(
                text,
                "\nconfig {} {}",
                section.section_type,
                quote(&section.name)
            )
            .unwrap();
            for (option, value) in &section.options {
                match value {
                    Value::Single(value) => writeln!(text, "\toption {option} {}", quote(value)),
                    Value::List(values) => values
                        .iter()
                        .try_for_each(|value| writeln!(text, "\tlist {option} {}", quote(value))),
                }
                .unwrap();
            }
        }

        text
    }

    #[test]
    fn what_splot_wrote_reads_back_as_nothing_to_change() {
        // Once the rendered config is in uci, the next apply finds nothing to stage.
        let network = example();
        let backend = OpenWrtBackend::new(Some(UciKeyStore::for_tests(PRIVATE_KEY)));

        for node in openwrt_nodes(&network) {
            let plan = plan::plan(&network, node.name()).unwrap();
            for (file, sections) in &backend.render(&plan).files {
                let read_back = export::parse(&exported(sections)).unwrap();
                assert_eq!(read_back, *sections, "{} {file}", node.name());
                assert!(diff::diff(&read_back, sections).is_empty());
            }
        }
    }

    #[test]
    fn example_config_snapshot() {
        let network = example();
        let backend = OpenWrtBackend::new(Some(UciKeyStore::for_tests(PRIVATE_KEY)));

        for node in openwrt_nodes(&network) {
            let plan = plan::plan(&network, node.name()).unwrap();

            let mut output = String::new();
            for (file, sections) in &backend.render(&plan).files {
                writeln!(output, "# {file}").unwrap();
                for command in sections.iter().flat_map(|section| section.commands(file)) {
                    writeln!(output, "{command}").unwrap();
                }
            }

            insta::assert_snapshot!(format!("example_{}", node.name()), output);
        }
    }
}
