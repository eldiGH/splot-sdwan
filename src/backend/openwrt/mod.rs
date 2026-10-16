//! OpenWrt: the plan as uci config, staged and committed with uci and made live
//! by reloading the services.

mod apply;
mod dhcp;
mod firewall;
mod naming;
mod network;
mod reload;
mod section;
pub mod splot_config;
pub mod uci;

use crate::{backend::Backend, plan::NodePlan};
pub use apply::Error;
use splot_config::SplotConfig;
use uci::UciBatchCommand;

/// The node's config as uci commands, file by file, in the order splot commits
/// the files.
pub struct Rendered {
    files: Vec<(&'static str, Vec<UciBatchCommand>)>,
}

impl Rendered {
    /// The uci files it writes.
    fn files(&self) -> Vec<&'static str> {
        self.files.iter().map(|(file, _)| *file).collect()
    }

    /// Every command, file by file.
    fn commands(&self) -> impl Iterator<Item = &UciBatchCommand> {
        self.files.iter().flat_map(|(_, commands)| commands)
    }
}

pub struct OpenWrtBackend {
    /// Where the node's private key lives.
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
                (
                    network::FILE,
                    network::render(plan, self.splot_config.mesh_key()),
                ),
                (firewall::FILE, firewall::render(plan)),
                (dhcp::FILE, dhcp::render(plan)),
            ],
        }
    }

    fn dry_run(&self, rendered: &Rendered) -> Result<(), Error> {
        apply::print(rendered)
    }

    fn apply(&self, rendered: &Rendered) -> Result<Vec<String>, Error> {
        let changed = apply::run(rendered)?;

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
            for (file, commands) in &backend.render(&plan).files {
                writeln!(output, "# {file}").unwrap();
                for command in commands {
                    writeln!(output, "{command}").unwrap();
                }
            }

            insta::assert_snapshot!(format!("example_{}", node.name()), output);
        }
    }
}
