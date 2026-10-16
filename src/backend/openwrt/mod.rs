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
mod section;
pub mod splot_config;
pub mod uci;

use crate::{backend::Backend, plan::NodePlan};
pub use apply::Error;
use section::{Section, Value};
use splot_config::SplotConfig;
use uci::UciBatchCommand;

/// The node's config as uci sections, file by file, in the order splot commits
/// the files.
pub struct Rendered {
    files: Vec<(&'static str, Vec<Section>)>,
}

impl Rendered {
    /// The uci files it writes.
    fn files(&self) -> Vec<&'static str> {
        self.files.iter().map(|(file, _)| *file).collect()
    }

    /// The commands that create every section, file by file.
    fn commands(&self) -> Vec<UciBatchCommand> {
        self.files
            .iter()
            .flat_map(|(file, sections)| sections.iter().flat_map(|section| section.commands(file)))
            .collect()
    }

    /// The same config with the node's private key where the placeholder is.
    fn with_private_key(&self, private_key: &str) -> Self {
        let fill = |(option, value): &(String, Value)| match value {
            Value::Single(value) if value == network::PRIVATE_KEY_PLACEHOLDER => {
                (option.clone(), Value::Single(private_key.to_owned()))
            }
            _ => (option.clone(), value.clone()),
        };
        let fill_section = |section: &Section| Section {
            options: section.options.iter().map(fill).collect(),
            ..section.clone()
        };

        Self {
            files: self
                .files
                .iter()
                .map(|(file, sections)| (*file, sections.iter().map(fill_section).collect()))
                .collect(),
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
        Rendered {
            files: vec![
                (network::FILE, network::render(plan)),
                (firewall::FILE, firewall::render(plan)),
                (dhcp::FILE, dhcp::render(plan)),
            ],
        }
    }

    fn dry_run(&self, rendered: &Rendered) -> Result<(), Error> {
        let private_key = self.splot_config.mesh_key();

        apply::print(&rendered.with_private_key(private_key), private_key)
    }

    fn apply(&self, rendered: &Rendered) -> Result<Vec<String>, Error> {
        let rendered = rendered.with_private_key(self.splot_config.mesh_key());
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
    fn apply_fills_in_the_private_key_and_nothing_else() {
        let rendered = Rendered {
            files: vec![
                (
                    "network",
                    vec![section(
                        "spl_mesh",
                        "interface",
                        &[
                            ("private_key", network::PRIVATE_KEY_PLACEHOLDER),
                            ("proto", "wireguard"),
                        ],
                    )],
                ),
                (
                    "dhcp",
                    vec![section("spl_host_printer", "host", &[("name", "printer")])],
                ),
            ],
        };

        let filled = rendered.with_private_key("REAL_KEY");

        let commands: Vec<String> = filled.commands().iter().map(ToString::to_string).collect();
        assert_eq!(
            commands,
            [
                "set network.spl_mesh='interface'",
                "set network.spl_mesh.private_key='REAL_KEY'",
                "set network.spl_mesh.proto='wireguard'",
                "set dhcp.spl_host_printer='host'",
                "set dhcp.spl_host_printer.name='printer'",
            ]
        );
        assert_eq!(filled.files(), ["network", "dhcp"]);
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
                assert!(diff::diff(file, &read_back, sections).is_empty());
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
