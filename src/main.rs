use clap::Parser;

use crate::{
    cli::{Cli, Command, PskCommand},
    config::Config,
    model::{Network, Validated, validator::types::ValidationWarning},
};
use anyhow::{Context, bail};

mod backend;
mod cli;
mod commands;
mod config;
mod consts;
mod env;
mod model;
mod plan;
mod process;
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
        Command::Init { node } => commands::init(&network, node),
        Command::Apply { dry_run } => commands::apply(&network, *dry_run),
        Command::Check => Ok(()),
        Command::Psk {
            command: PskCommand::Set { peer },
        } => commands::psk_set(&network, peer),
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
