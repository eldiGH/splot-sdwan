use anyhow::bail;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::{
    agent::{self, Agent},
    consts,
    types::{identifier::Identifier, platform::Os, ssh::SshDestination},
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
    /// a host of ~/.ssh/config). Without it, at the node's platform.ssh; without
    /// that, splot acts on the machine it runs on
    #[arg(long, value_name = "DESTINATION")]
    ssh: Option<SshDestination>,
    /// Act on the machine splot runs on, even when the config gives the node a
    /// platform.ssh
    #[arg(long, conflicts_with = "ssh")]
    local: bool,
    /// Send the node this agent instead of the one splot carries for its CPU
    #[arg(long, value_name = "FILE", conflicts_with = "local")]
    agent: Option<PathBuf>,
}

impl Reach {
    /// Where the node is: at `--ssh`, else at `configured` (its platform.ssh);
    /// none for the machine splot runs on.
    fn destination<'a>(
        &'a self,
        configured: Option<&'a SshDestination>,
    ) -> Option<&'a SshDestination> {
        if self.local {
            return None;
        }
        self.ssh.as_ref().or(configured)
    }

    /// The agent on the node this reaches, `configured` its platform.ssh.
    pub fn agent(&self, configured: Option<&SshDestination>) -> anyhow::Result<Agent> {
        let destination = self.destination(configured);
        if destination.is_none() && self.agent.is_some() {
            bail!(
                "--agent is sent to the node over ssh, and the config gives it no platform.ssh: give --ssh"
            );
        }

        Ok(Agent::new(destination.cloned(), self.agent.clone()))
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
        /// Seconds the node waits for splot to reach it again and confirm the
        /// change: it puts back what it had otherwise
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = consts::DEFAULT_CONFIRM_WITHIN,
            value_parser = clap::value_parser!(u32).range(10..),
            conflicts_with = "dry_run"
        )]
        confirm_within: u32,
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
        let reach = reach(&["--ssh", "root@router"]);
        assert_eq!(
            reach.ssh.as_ref().map(SshDestination::as_str),
            Some("root@router")
        );
        assert_eq!(reach.agent, None);

        // Never an option of ssh's.
        assert!(
            Cli::try_parse_from([
                "splot",
                "apply",
                "--node",
                "Home",
                "--ssh=-oProxyCommand=sh"
            ])
            .is_err()
        );
    }

    /// The `Reach` of `apply --node Home` with `args`.
    fn reach(args: &[&str]) -> Reach {
        let cli = parse(&[&["splot", "apply", "--node", "Home"], args].concat());
        let Some(Command::Apply { reach, .. }) = cli.command else {
            panic!("not apply");
        };
        reach
    }

    #[test]
    fn a_node_is_reached_at_ssh_else_at_its_platform_ssh_else_here() {
        let configured: SshDestination = "root@192.168.1.1".parse().unwrap();
        let destination = |args: &[&str], configured: Option<&SshDestination>| {
            reach(args).destination(configured).map(ToString::to_string)
        };

        assert_eq!(
            destination(&["--ssh", "router"], Some(&configured)).as_deref(),
            Some("router")
        );
        assert_eq!(
            destination(&[], Some(&configured)).as_deref(),
            Some("root@192.168.1.1")
        );
        assert_eq!(destination(&[], None), None);
        assert_eq!(destination(&["--local"], Some(&configured)), None);

        // Here, or over ssh at one destination: not both.
        assert!(
            Cli::try_parse_from([
                "splot", "apply", "--node", "Home", "--local", "--ssh", "router"
            ])
            .is_err()
        );
    }

    #[test]
    fn an_agent_is_sent_over_ssh_only() {
        let configured: SshDestination = "root@192.168.1.1".parse().unwrap();

        // To the node's platform.ssh, or --ssh.
        assert!(matches!(
            reach(&["--agent", "./agent"]).agent(Some(&configured)),
            Ok(Agent::Remote { destination, agent: Some(_), .. }) if destination == configured
        ));
        assert!(matches!(
            reach(&["--ssh", "router", "--agent", "./agent"]).agent(None),
            Ok(Agent::Remote { agent: Some(_), .. })
        ));
        // Nowhere to send it.
        let err = reach(&["--agent", "./agent"]).agent(None).err().unwrap();
        assert_eq!(
            err.to_string(),
            "--agent is sent to the node over ssh, and the config gives it no platform.ssh: give --ssh"
        );
        assert!(
            Cli::try_parse_from([
                "splot", "apply", "--node", "Home", "--local", "--agent", "./a"
            ])
            .is_err()
        );
        // Without either, here.
        assert!(matches!(reach(&[]).agent(None), Ok(Agent::Local(_))));
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
