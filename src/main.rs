use clap::Parser;

use crate::{
    cli::{Cli, Command},
    config::Config,
    managers::{
        NodeContext, dhcp::DhcpManager, firewall::FirewallManager, network::NetworkManager,
    },
    model::{Network, Validated, validator::types::ValidationWarning},
    pipeline::UciPipeline,
};
use anyhow::{Context, bail};

pub mod cli;
pub mod config;
pub mod consts;
pub mod env;
pub mod managers;
pub mod model;
pub mod pipeline;
pub mod protocol;
pub mod splot_config;
#[cfg(test)]
pub(crate) mod test_support;
pub mod types;
pub mod uci;
pub mod wg;

fn main() -> anyhow::Result<()> {
    env::init();
    env_logger::init();

    let cli = Cli::parse();

    let Some(command) = cli.command() else {
        return Ok(());
    };

    let config = Config::parse_file(&cli.config_path())
        .with_context(|| format!("failed to load config from {}", cli.config_path().display()))?;

    let Some(network) = validate(&config) else {
        bail!("there are errors in your config file");
    };

    match command {
        Command::Apply { dry_run } => {
            let splot_config = splot_config::SplotConfig::load()?;
            let own_public_key = wg::get_pubkey(splot_config.mesh_key())
                .context("failed to derive this router's public key")?;
            let Some((own_name, own_node)) = config.find_node_by_public_key(&own_public_key) else {
                bail!(
                    "this router's public key was not found in the splot config - add this node and try again"
                );
            };

            let pipeline = UciPipeline::new()
                .register(NetworkManager)
                .register(FirewallManager)
                .register(DhcpManager);

            let node_context = NodeContext {
                own_name,
                own_node,
                splot_config: &splot_config,
            };

            if *dry_run {
                pipeline.print(&config, &network, &node_context)?;
            } else {
                let changed = pipeline.run(&config, &network, &node_context)?;

                if changed.is_empty() {
                    println!("Nothing changed.");
                } else {
                    println!("Applied and reloaded: {}", changed.join(", "));
                }
            }
        }

        Command::Check => {}
    }

    Ok(())
}

/// Validates the config and prints what validation found. `None` when it has
/// errors.
fn validate(config: &Config) -> Option<Network> {
    match model::validate(config) {
        Ok(Validated { network, warnings }) => {
            print_warnings(&warnings);

            Some(network)
        }
        Err(report) => {
            for error in &report.errors {
                eprintln!("error: {error}");
            }
            print_warnings(&report.warnings);

            eprintln!();
            eprintln!(
                "validation failed: {} error(s), {} warning(s)",
                report.errors.len(),
                report.warnings.len()
            );

            None
        }
    }
}

fn print_warnings(warnings: &[ValidationWarning]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}
