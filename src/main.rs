use clap::Parser;

use crate::{
    backend::{
        Backend,
        openwrt::{OpenWrtBackend, splot_config::SplotConfig},
    },
    cli::{Cli, Command, PskCommand},
    config::Config,
    model::{Network, Validated, validator::types::ValidationWarning},
    plan::NodePlan,
};
use anyhow::{Context, bail};

mod backend;
mod cli;
mod config;
mod consts;
mod env;
mod model;
mod plan;
mod process;
mod protocol;
#[cfg(test)]
pub(crate) mod test_support;
mod types;
mod wg;

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
            let splot_config = SplotConfig::load()?;
            let plan = own_plan(&network, &splot_config)?;

            let backend = OpenWrtBackend::new(splot_config);
            let rendered = backend.render(&plan);

            if *dry_run {
                backend.dry_run(&rendered)?;
            } else {
                let changed = backend.apply(&rendered)?;

                if changed.is_empty() {
                    println!("Nothing changed.");
                } else {
                    println!("Applied and reloaded: {}", changed.join(", "));
                }
            }
        }

        Command::Check => {}

        Command::Psk {
            command: PskCommand::Set { peer },
        } => {
            let splot_config = SplotConfig::load()?;
            let plan = own_plan(&network, &splot_config)?;

            let Some(peer) = plan.wireguard.peer(peer) else {
                let peers: Vec<String> = plan
                    .wireguard
                    .peers
                    .iter()
                    .map(|peer| peer.host.to_string())
                    .collect();
                bail!(
                    "'{peer}' isn't a peer of {}; its peers are {}",
                    plan.node,
                    peers.join(", ")
                );
            };
            if !peer.psk {
                bail!(
                    "{}'s pair with {} uses no preshared key: one of them sets `psk: false`",
                    plan.node,
                    peer.host
                );
            }

            let mut key = String::new();
            std::io::stdin()
                .read_line(&mut key)
                .context("failed to read the preshared key from stdin")?;
            SplotConfig::store_psk(&peer.host, key.trim())?;

            println!(
                "Stored the preshared key of {}'s pair with {}.",
                plan.node, peer.host
            );
        }
    }

    Ok(())
}

/// This router's plan: the node whose public key follows from the local private
/// key.
fn own_plan(network: &Network, splot_config: &SplotConfig) -> anyhow::Result<NodePlan> {
    let own_public_key = wg::get_pubkey(splot_config.mesh_key())
        .context("failed to derive this router's public key")?;

    network
        .find_node_by_public_key(&own_public_key)
        .and_then(|node| plan::plan(network, node.name()))
        .context(
            "this router's public key was not found in the splot config - add this node and try again",
        )
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
