use clap::Parser;

use crate::{
    cli::{Cli, Command, PskCommand},
    config::Config,
    model::{Network, Validated, validator::types::ValidationWarning},
};
use anyhow::{Context, bail};

mod agent;
mod backend;
mod cli;
mod commands;
mod config;
mod consts;
mod env;
mod model;
mod plan;
#[cfg(test)]
pub(crate) mod test_support;
mod types;

fn main() -> anyhow::Result<()> {
    // Started again to keep the deadline of a run it applied here.
    splot_agent::watch_if_asked();
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

    // A node is reached where the command says, else at its platform.ssh.
    let configured = |node| network.node(node).and_then(|node| node.platform().ssh());

    match command {
        Command::Init { node, os, reach } => {
            commands::init(&network, node, *os, &mut reach.agent(configured(node))?)
        }
        Command::Apply {
            node,
            dry_run,
            confirm_within,
            reach,
        } => commands::apply(
            &network,
            node,
            *dry_run,
            *confirm_within,
            &mut reach.agent(configured(node))?,
        ),
        Command::Check => Ok(()),
        Command::Psk {
            command: PskCommand::Set { node, peer, reach },
        } => commands::psk_set(&network, node, peer, &mut reach.agent(configured(node))?),
    }
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
