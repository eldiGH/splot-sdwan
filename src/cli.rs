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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn config_path_defaults_to_splot_yml() {
        let cli = parse(&["splot", "check"]);
        assert_eq!(cli.config_path(), PathBuf::from("splot.yml"));
    }

    #[test]
    fn config_path_uses_provided_value() {
        let cli = parse(&["splot", "--config", "/etc/splot.yml", "check"]);
        assert_eq!(cli.config_path(), PathBuf::from("/etc/splot.yml"));
    }

    #[test]
    fn no_subcommand_gives_no_command() {
        let cli = parse(&["splot"]);
        assert!(cli.command().is_none());
    }

    #[test]
    fn check_subcommand() {
        let cli = parse(&["splot", "check"]);
        assert!(matches!(cli.command(), Some(Command::Check)));
    }

    #[test]
    fn apply_subcommand_defaults_dry_run_false() {
        let cli = parse(&["splot", "apply"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Apply { dry_run: false })
        ));
    }

    #[test]
    fn apply_dry_run_flag() {
        let cli = parse(&["splot", "apply", "--dry-run"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Apply { dry_run: true })
        ));
    }
}
