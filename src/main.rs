use std::process;

use clap::Parser;

use crate::{
    cli::{Cli, Command},
    config::Config,
    managers::{dhcp::DhcpManager, firewall::FirewallManager, network::NetworkManager},
    pipeline::UciPipeline,
};

pub mod cli;
pub mod config;
pub mod consts;
pub mod env;
pub mod managers;
pub mod naming;
pub mod pipeline;
pub mod protocol;
pub mod splot_config;
#[cfg(test)]
pub(crate) mod test_support;
pub mod types;
pub mod uci;
pub mod validator;
pub mod wg;

fn main() {
    env::init();
    env_logger::init();

    let cli = Cli::parse();

    let Some(command) = cli.command() else {
        return;
    };

    let config = Config::parse_file(&cli.config_path()).unwrap();

    if report_issues(&config) {
        process::exit(1);
    }

    match command {
        Command::Apply { dry_run } => {
            let private_key = splot_config::ensure_initialized();

            let own_name = config
                .find_node_name_by_public_key(&wg::get_pubkey(&private_key))
                .unwrap_or_else(|| {
                    eprintln!(
                        "Error: this router's public key was not found in splot config file."
                    );
                    eprintln!("Add this node to the config and try again.");
                    std::process::exit(1);
                });

            let pipeline = UciPipeline::new()
                .register(NetworkManager)
                .register(FirewallManager)
                .register(DhcpManager);

            if *dry_run {
                pipeline.print(&config, own_name);
            } else {
                pipeline.run(&config, own_name);
            }
        }

        Command::Check => {}
    }
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
