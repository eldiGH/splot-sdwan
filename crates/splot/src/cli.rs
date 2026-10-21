use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::{
    agent::{self, Agent},
    types::{identifier::Identifier, platform::Os},
};

#[derive(Parser)]
#[command(version = agent::VERSION.as_str(), about, long_about = None)]
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

/// Where the node a command acts on is.
#[derive(Args)]
pub struct Reach {
    /// Reach the node over ssh at DESTINATION, anything ssh takes (`root@router`,
    /// a host of ~/.ssh/config). Without it, splot acts on the machine it runs on
    #[arg(long, value_name = "DESTINATION")]
    ssh: Option<String>,
    /// Send the node this agent instead of the one splot carries for its CPU
    #[arg(long, value_name = "FILE", requires = "ssh")]
    agent: Option<PathBuf>,
}

impl Reach {
    /// The agent on the node this reaches.
    pub fn agent(&self) -> Agent {
        Agent::new(self.ssh.clone(), self.agent.clone())
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Give this peer its WireGuard key (only if it has none) and say what the
    /// config needs for NODE
    Init {
        /// The node this peer is, as the config names it
        #[arg(long)]
        node: Identifier,
        /// The OS this peer runs (openwrt, linux), for a node the config doesn't
        /// have yet: it decides where the key is kept. Detected when left out
        #[arg(long)]
        os: Option<Os>,
        #[command(flatten)]
        reach: Reach,
    },

    /// Make the node hold what the config says it should
    Apply {
        /// The node this peer is, as the config names it
        #[arg(long)]
        node: Identifier,
        #[command(flatten)]
        reach: Reach,
        /// Show what apply would change, changing nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// Validate the config and report all errors and warnings
    Check,

    /// Manage the preshared keys of this peer's WireGuard pairs
    Psk {
        #[command(subcommand)]
        command: PskCommand,
    },
}

#[derive(Subcommand)]
pub enum PskCommand {
    /// Store the preshared key of this peer's pair with PEER, read from stdin
    /// (e.g. `wg genpsk`). The same key goes on the peer's side.
    Set {
        /// The node this peer is, as the config names it
        #[arg(long)]
        node: Identifier,
        /// The peer, as the config names it: `Cabin`, `Phone`, `Home.camera`
        peer: String,
        #[command(flatten)]
        reach: Reach,
    },
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
        let cli = parse(&["splot", "apply", "--node", "Home"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Apply { node, dry_run: false, .. }) if node.as_ref() == "Home"
        ));
    }

    #[test]
    fn a_command_that_acts_on_a_node_needs_its_name() {
        for args in [
            &["splot", "apply"][..],
            &["splot", "apply", "--dry-run"],
            &["splot", "psk", "set", "Cabin"],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn init_names_the_node() {
        let cli = parse(&["splot", "init", "--node", "Cabin"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Init { node, os: None, .. }) if node.as_ref() == "Cabin"
        ));
        // Without one, or with one that isn't a name, it's a usage error.
        assert!(Cli::try_parse_from(["splot", "init"]).is_err());
        assert!(Cli::try_parse_from(["splot", "init", "--node", "a b"]).is_err());
    }

    #[test]
    fn init_may_name_the_peers_os() {
        let cli = parse(&["splot", "init", "--node", "Barn", "--os", "linux"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Init {
                os: Some(Os::Linux),
                ..
            })
        ));
        assert!(Cli::try_parse_from(["splot", "init", "--node", "Barn", "--os", "bsd"]).is_err());
    }

    #[test]
    fn psk_set_names_the_peer() {
        let cli = parse(&["splot", "psk", "set", "--node", "Cabin", "Home.camera"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Psk {
                command: PskCommand::Set { node, peer, .. }
            }) if node.as_ref() == "Cabin" && peer == "Home.camera"
        ));
    }

    #[test]
    fn a_command_on_a_node_may_reach_it_over_ssh_and_send_it_an_agent() {
        for args in [
            &["splot", "apply", "--node", "Home", "--ssh", "root@router"][..],
            &[
                "splot", "init", "--node", "Home", "--ssh", "router", "--agent", "./agent",
            ],
            &[
                "splot", "psk", "set", "--node", "Home", "Cabin", "--ssh", "router",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
        let cli = parse(&["splot", "apply", "--node", "Home", "--ssh", "root@router"]);
        let Some(Command::Apply { reach, .. }) = cli.command() else {
            panic!("not apply");
        };
        assert_eq!(reach.ssh.as_deref(), Some("root@router"));
        assert_eq!(reach.agent, None);

        // An agent is sent over ssh only.
        assert!(
            Cli::try_parse_from(["splot", "apply", "--node", "Home", "--agent", "./agent"])
                .is_err()
        );
    }

    #[test]
    fn apply_dry_run_flag() {
        let cli = parse(&["splot", "apply", "--node", "Home", "--dry-run"]);
        assert!(matches!(
            cli.command(),
            Some(Command::Apply { dry_run: true, .. })
        ));
    }
}
