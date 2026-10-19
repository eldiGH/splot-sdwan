//! OpenWrt: the plan as uci config, staged and committed with uci and made live
//! by reloading the services.

mod apply;
mod dhcp;
mod diff;
mod export;
mod firewall;
mod naming;
mod network;
mod reload;
mod secret;
mod section;
pub mod splot_config;
pub mod uci;

use crate::{backend::Backend, plan::NodePlan};
pub use apply::Error;
use secret::{Secret, Slot};
use section::{Section, Value};
use splot_config::SplotConfig;

/// The node's config as uci sections, file by file, in the order splot commits
/// the files, with placeholders where its secrets go.
pub struct Rendered {
    files: Vec<(&'static str, Vec<Section>)>,
    /// Where its secrets go: apply fills them in, the dry run masks them again.
    secrets: Vec<Slot>,
}

impl Rendered {
    /// The uci files it writes.
    fn files(&self) -> Vec<&'static str> {
        self.files.iter().map(|(file, _)| *file).collect()
    }

    /// The same config with the node's secrets in their slots.
    fn with_secrets(&self, private_key: &str) -> Self {
        let value = |secret: &Secret| match secret {
            Secret::PrivateKey => private_key,
        };

        let mut files = self.files.clone();
        for slot in &self.secrets {
            let option = files
                .iter_mut()
                .filter(|(file, _)| *file == slot.file)
                .flat_map(|(_, sections)| sections.iter_mut())
                .filter(|section| section.name == slot.section)
                .flat_map(|section| section.options.iter_mut())
                .find(|(option, _)| option == slot.option);

            if let Some((_, option_value)) = option {
                *option_value = Value::Single(value(&slot.secret).to_owned());
            }
        }

        Self {
            files,
            secrets: self.secrets.clone(),
        }
    }
}

pub struct OpenWrtBackend {
    /// Where the node's private key lives: `apply` fills it into the rendered
    /// config.
    splot_config: SplotConfig,
}

impl OpenWrtBackend {
    pub fn new(splot_config: SplotConfig) -> Self {
        Self { splot_config }
    }
}

impl Backend for OpenWrtBackend {
    type Rendered = Rendered;
    type Error = Error;

    fn render(&self, plan: &NodePlan) -> Rendered {
        let (network, secrets) = network::render(plan);

        Rendered {
            files: vec![
                (network::FILE, network),
                (firewall::FILE, firewall::render(plan)),
                (dhcp::FILE, dhcp::render(plan)),
            ],
            secrets,
        }
    }

    fn dry_run(&self, rendered: &Rendered) -> Result<(), Error> {
        apply::print(&rendered.with_secrets(self.splot_config.mesh_key()))
    }

    fn apply(&self, rendered: &Rendered) -> Result<Vec<String>, Error> {
        let rendered = rendered.with_secrets(self.splot_config.mesh_key());
        let changed = apply::run(&rendered)?;

        Ok(changed.into_iter().map(str::to_owned).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;
    use crate::{plan, test_support};

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
        };

        let filled = rendered.with_secrets("REAL_KEY");

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
                "set network.spl_mesh.private_key='REAL_KEY'",
            ]
        );
        assert_eq!(filled.files(), ["dhcp", "network"]);
        assert_eq!(filled.secrets, rendered.secrets);
    }

    #[test]
    fn every_slot_holds_its_placeholder_and_every_placeholder_has_a_slot() {
        let network = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        let backend = OpenWrtBackend::new(SplotConfig::for_tests("FAKE_MESH_KEY"));

        for node in network.nodes() {
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
        let network = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        let backend = OpenWrtBackend::new(SplotConfig::for_tests("FAKE_MESH_KEY"));

        for node in network.nodes() {
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
        let network = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        let backend = OpenWrtBackend::new(SplotConfig::for_tests("FAKE_MESH_KEY"));

        for node in network.nodes() {
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
