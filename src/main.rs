use clap::Parser;

use crate::{
    cli::{Cli, Command},
    config::Config,
    managers::{
        NodeContext, dhcp::DhcpManager, firewall::FirewallManager, network::NetworkManager,
    },
    pipeline::UciPipeline,
};
use anyhow::{Context, bail};

pub mod cli;
pub mod config;
pub mod consts;
pub mod env;
pub mod managers;
pub mod pipeline;
pub mod protocol;
pub mod splot_config;
#[cfg(test)]
pub(crate) mod test_support;
pub mod types;
pub mod uci;
pub mod validator;
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

    if report_issues(&config) {
        bail!("there are errors in your config file");
    }

    match command {
        Command::Apply { dry_run } => {
            let mut splot_config = splot_config::SplotConfig::load()?;
            let own_public_key = wg::get_pubkey(splot_config.mesh_key())
                .context("failed to derive this router's public key")?;
            let Some((own_name, own_node)) = config.find_node_by_public_key(&own_public_key) else {
                bail!(
                    "this router's public key was not found in the splot config - add this node and try again"
                );
            };

            splot_config.ensure_vpn_keys(own_node.vpn_interfaces.keys())?;

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
                pipeline.print(&config, &node_context)?;
            } else {
                let changed = pipeline.run(&config, &node_context)?;

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

fn report_issues(config: &Config) -> bool {
    let report = validator::validate_config(config);

    for error in &report.errors {
        eprintln!("error: {error}");
    }

    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }

    if !report.errors.is_empty() {
        eprintln!();
        eprintln!(
            "validation failed: {} error(s), {} warning(s)",
            report.errors.len(),
            report.warnings.len()
        );
    }

    !report.errors.is_empty()
}
