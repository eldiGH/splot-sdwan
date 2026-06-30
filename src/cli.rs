use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| PathBuf::from("splot.yml"))
    }

    pub fn command(&self) -> Option<&Command> {
        self.command.as_ref()
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Apply the config to this router using uci
    Apply {
        #[arg(
            long,
            help = "Print the uci commands that would run without executing them"
        )]
        dry_run: bool,
    },

    /// Validate the config and report all errors and warnings
    Check,
}
