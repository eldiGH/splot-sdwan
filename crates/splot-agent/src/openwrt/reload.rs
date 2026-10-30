//! Making committed config live on OpenWrt. `uci commit` only writes files: the
//! services keep running the old config until something reloads them.
//!
//! procd reloads them by itself, but a second after `reload_config`, later than
//! a run's check: so the reloads the check depends on run here too, and the
//! change is live when they return. netifd's are requests that return at once
//! (it restarts the interface afterwards, independently of splot's session), so
//! a reload that briefly drops the mesh can't cut splot off halfway; fw4 loads
//! its whole ruleset at once, and lets established traffic through.

use std::{
    fmt::{self, Display},
    process::Command,
};

use log::info;

use super::contested::FIREWALL;
use crate::process;

/// The uci file of the network interfaces, the WireGuard ones among them.
pub(super) const NETWORK: &str = "network";

/// The uci file dnsmasq serves DHCP and DNS from.
const DHCP: &str = "dhcp";

/// How a WireGuard interface picks up changed peers.
///
/// netifd's reload compares only an interface's own options (key, port,
/// addresses); peers live in separate `wireguard_<interface>` sections, so a
/// peer-only change needs one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerUpdate {
    /// `renew`: netifd re-runs the WireGuard setup, which applies the peers with
    /// `wg syncconf`. Live: tunnels stay up. Needs a handler with renew support
    /// (OpenWrt 25.12+).
    Renew,
    /// `down` + `up`: the interface is torn down and set up again, so its tunnels
    /// drop for a moment.
    Restart,
}

/// One command of a reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadCommand {
    program: &'static str,
    args: Vec<String>,
}

impl ReloadCommand {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    fn ubus(args: &[&str]) -> Self {
        Self::new("ubus", args)
    }
}

impl Display for ReloadCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }

        Ok(())
    }
}

/// What has to run after a commit for the new config to take effect.
#[derive(Debug)]
pub struct Reload {
    /// splot's WireGuard interface, when `network` changed.
    wireguard_interface: Option<String>,
    peer_update: PeerUpdate,
    /// Whether `firewall` changed.
    firewall: bool,
    /// Whether `dhcp` changed.
    dhcp: bool,
}

impl Reload {
    /// `None` when no file changed.
    pub fn new(
        changed_files: &[String],
        wireguard_interface: String,
        peer_update: PeerUpdate,
    ) -> Option<Self> {
        if changed_files.is_empty() {
            return None;
        }
        let changed = |name: &str| changed_files.iter().any(|file| file == name);

        Some(Self {
            wireguard_interface: changed(NETWORK).then_some(wireguard_interface),
            peer_update,
            firewall: changed(FIREWALL),
            dhcp: changed(DHCP),
        })
    }

    /// The same reload, without bringing splot's WireGuard interface up: for
    /// when it's gone.
    pub fn without_interface(self) -> Self {
        Self {
            wireguard_interface: None,
            ..self
        }
    }

    /// The commands, in order.
    pub fn commands(&self) -> Vec<ReloadCommand> {
        self.steps().into_iter().flatten().collect()
    }

    /// The commands, in steps: every step runs, and in each a command runs only
    /// once the one before it succeeded.
    fn steps(&self) -> Vec<Vec<ReloadCommand>> {
        // Tells procd which files changed: a second later, it reloads every
        // service that reads one (netifd, fw4, dnsmasq, and others such as
        // odhcpd), those below again, with the same files.
        let mut steps = vec![vec![ReloadCommand::new("reload_config", &[])]];

        if let Some(interface) = &self.wireguard_interface {
            // netifd re-reads the config now, so the peer update below reaches
            // the interface even when it's new in this commit.
            steps.push(vec![ReloadCommand::ubus(&["call", "network", "reload"])]);

            let object = format!("network.interface.{interface}");
            match self.peer_update {
                PeerUpdate::Renew => {
                    steps.push(vec![ReloadCommand::ubus(&["call", &object, "renew"])]);
                }
                PeerUpdate::Restart => {
                    // Up again even when `down` failed.
                    steps.push(vec![ReloadCommand::ubus(&["call", &object, "down"])]);
                    steps.push(vec![ReloadCommand::ubus(&["call", &object, "up"])]);
                }
            }
        }

        if self.firewall {
            // `fw4 reload` returns once the ruleset is loaded, but exits 0 when
            // nft refuses it (the old one stays live): so it's checked first.
            steps.push(vec![
                ReloadCommand::new("fw4", &["check"]),
                ReloadCommand::new("/etc/init.d/firewall", &["reload"]),
            ]);
        }

        if self.dhcp {
            // procd restarts dnsmasq with its new config before this returns.
            steps.push(vec![ReloadCommand::new("/etc/init.d/dnsmasq", &["reload"])]);
        }

        steps
    }

    /// Runs every step, even after one failed, and reports all failures.
    pub fn run(&self) -> Result<(), Error> {
        run_steps(&self.steps(), |command| {
            info!("Running `{command}`");
            run(command).map(drop)
        })
    }
}

/// Runs `steps` with `run`: every step, but in each, a command only once the one
/// before it succeeded. Reports every failure.
fn run_steps(
    steps: &[Vec<ReloadCommand>],
    mut run: impl FnMut(&ReloadCommand) -> Result<(), Error>,
) -> Result<(), Error> {
    let failures: Vec<Error> = steps
        .iter()
        .filter_map(|step| step.iter().find_map(|command| run(command).err()))
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Reload(failures))
    }
}

/// Runs `command` and returns its stdout. A non-zero exit is an error.
fn run(command: &ReloadCommand) -> Result<String, Error> {
    let mut program = Command::new(command.program);
    program.args(&command.args);
    // It gets no input, so it fails to run the way it fails to start.
    let output = process::run(program, None).map_err(|err| match err {
        process::Error::Spawn(err) | process::Error::Io(err) => Error::Spawn(command.program, err),
    })?;

    if !output.status.success() {
        return Err(Error::Failed {
            command: command.to_string(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Asks netifd whether its WireGuard handler supports renew.
pub fn peer_update() -> Result<PeerUpdate, Error> {
    let handlers = run(&ReloadCommand::ubus(&[
        "call",
        "network",
        "get_proto_handlers",
    ]))?;

    peer_update_from_handlers(&handlers)
}

fn peer_update_from_handlers(json: &str) -> Result<PeerUpdate, Error> {
    let handlers: serde_json::Value = serde_json::from_str(json).map_err(Error::BadHandlerList)?;
    let wireguard = handlers.get("wireguard").ok_or(Error::NoWireguardHandler)?;

    // A missing flag means an older netifd: no renew.
    let renew_available = wireguard
        .get("renew_available")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok(if renew_available {
        PeerUpdate::Renew
    } else {
        PeerUpdate::Restart
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to run {0} - is this an OpenWrt router?")]
    Spawn(&'static str, #[source] std::io::Error),
    #[error("`{command}` failed (exit code {code:?}): {stderr}")]
    Failed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("unexpected answer from `ubus call network get_proto_handlers`")]
    BadHandlerList(#[source] serde_json::Error),
    #[error("netifd has no WireGuard protocol handler - is wireguard-tools installed?")]
    NoWireguardHandler,
    #[error(
        "the config is committed, but reloading it failed: {}",
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
    )]
    Reload(Vec<Error>),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shaped like `ubus call network get_proto_handlers` (netifd's
    // `proto_dump_handlers`), trimmed to two handlers.
    fn handlers(renew_available: &str) -> String {
        format!(
            r#"{{
                "static": {{ "immediate": true, "renew_available": false }},
                "wireguard": {{
                    "validate": {{ "private_key": "string" }},
                    "immediate": false,
                    "no_device": true,
                    "renew_available": {renew_available},
                    "no_task": true
                }}
            }}"#
        )
    }

    #[test]
    fn handler_with_renew_updates_peers_live() {
        // OpenWrt 25.12's wireguard.sh sets renew_handler=1.
        assert_eq!(
            peer_update_from_handlers(&handlers("true")).unwrap(),
            PeerUpdate::Renew
        );
    }

    #[test]
    fn handler_without_renew_restarts_the_interface() {
        // OpenWrt 24.10: netifd ignores a renew it can't run, silently.
        assert_eq!(
            peer_update_from_handlers(&handlers("false")).unwrap(),
            PeerUpdate::Restart
        );
    }

    #[test]
    fn missing_wireguard_handler_is_an_error() {
        let result = peer_update_from_handlers(r#"{ "static": { "renew_available": false } }"#);
        assert!(
            matches!(result, Err(Error::NoWireguardHandler)),
            "{result:?}"
        );
    }

    #[test]
    fn unreadable_answer_is_an_error() {
        let result = peer_update_from_handlers("Command failed: Not found");
        assert!(
            matches!(result, Err(Error::BadHandlerList(_))),
            "{result:?}"
        );
    }

    fn mesh() -> String {
        "spl_mesh".to_owned()
    }

    #[test]
    fn nothing_changed_nothing_to_reload() {
        assert!(Reload::new(&[], mesh(), PeerUpdate::Renew).is_none());
    }

    fn rendered(reload: &Reload) -> Vec<String> {
        reload
            .commands()
            .iter()
            .map(|command| command.to_string())
            .collect()
    }

    #[test]
    fn firewall_change_reloads_without_touching_the_tunnels() {
        // fw4 itself, checked first, rather than procd a second later.
        let reload = Reload::new(&["firewall".to_owned()], mesh(), PeerUpdate::Restart).unwrap();
        assert_eq!(
            rendered(&reload),
            ["reload_config", "fw4 check", "/etc/init.d/firewall reload"]
        );
    }

    #[test]
    fn dhcp_change_reloads_dnsmasq() {
        let reload = Reload::new(&["dhcp".to_owned()], mesh(), PeerUpdate::Restart).unwrap();
        assert_eq!(
            rendered(&reload),
            ["reload_config", "/etc/init.d/dnsmasq reload"]
        );
    }

    #[test]
    fn network_change_renews_the_wireguard_interface() {
        // netifd re-reads the config first (procd would only do it a second
        // later): a renew can't reach an interface netifd doesn't know yet.
        let reload = Reload::new(
            &["network".to_owned(), "dhcp".to_owned()],
            mesh(),
            PeerUpdate::Renew,
        )
        .unwrap();
        assert_eq!(
            rendered(&reload),
            [
                "reload_config",
                "ubus call network reload",
                "ubus call network.interface.spl_mesh renew",
                "/etc/init.d/dnsmasq reload",
            ]
        );
    }

    #[test]
    fn every_file_changed_reloads_every_service() {
        let reload = Reload::new(
            &[
                "dhcp".to_owned(),
                "firewall".to_owned(),
                "network".to_owned(),
            ],
            mesh(),
            PeerUpdate::Renew,
        )
        .unwrap();
        assert_eq!(
            rendered(&reload),
            [
                "reload_config",
                "ubus call network reload",
                "ubus call network.interface.spl_mesh renew",
                "fw4 check",
                "/etc/init.d/firewall reload",
                "/etc/init.d/dnsmasq reload",
            ]
        );
    }

    #[test]
    fn without_the_interface_the_other_services_still_reload() {
        let reload = Reload::new(
            &["firewall".to_owned(), "network".to_owned()],
            mesh(),
            PeerUpdate::Renew,
        )
        .unwrap()
        .without_interface();
        assert_eq!(
            rendered(&reload),
            ["reload_config", "fw4 check", "/etc/init.d/firewall reload"]
        );
    }

    /// Runs `reload` with every command in `failing` failing, and returns the
    /// commands it ran, in order, and the failures it reported.
    fn ran(reload: &Reload, failing: &[&str]) -> (Vec<String>, Vec<String>) {
        let mut ran = Vec::new();
        let result = run_steps(&reload.steps(), |command| {
            let command = command.to_string();
            let fails = failing.contains(&command.as_str());
            ran.push(command.clone());
            if fails {
                Err(Error::Failed {
                    command,
                    code: Some(1),
                    stderr: String::new(),
                })
            } else {
                Ok(())
            }
        });
        let failures = match result {
            Ok(()) => Vec::new(),
            Err(Error::Reload(failures)) => failures
                .iter()
                .map(|failure| match failure {
                    Error::Failed { command, .. } => command.clone(),
                    other => panic!("{other:?}"),
                })
                .collect(),
            Err(other) => panic!("{other:?}"),
        };

        (ran, failures)
    }

    #[test]
    fn a_ruleset_nft_refuses_is_not_reloaded_and_fails_the_reload() {
        // `fw4 reload` exits 0 when nft refuses the ruleset, so the check is
        // what fails; the other services still reload.
        let reload = Reload::new(
            &["dhcp".to_owned(), "firewall".to_owned()],
            mesh(),
            PeerUpdate::Renew,
        )
        .unwrap();
        assert_eq!(
            ran(&reload, &["fw4 check"]),
            (
                vec![
                    "reload_config".to_owned(),
                    "fw4 check".to_owned(),
                    "/etc/init.d/dnsmasq reload".to_owned(),
                ],
                vec!["fw4 check".to_owned()],
            )
        );
    }

    #[test]
    fn every_command_runs_when_all_succeed() {
        let reload = Reload::new(
            &[
                "dhcp".to_owned(),
                "firewall".to_owned(),
                "network".to_owned(),
            ],
            mesh(),
            PeerUpdate::Restart,
        )
        .unwrap();
        let (ran, failures) = ran(&reload, &[]);
        assert_eq!(ran, rendered(&reload));
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn every_failure_is_reported_and_the_rest_still_runs() {
        // A failed `down` doesn't keep the interface from coming up again.
        let reload = Reload::new(
            &["firewall".to_owned(), "network".to_owned()],
            mesh(),
            PeerUpdate::Restart,
        )
        .unwrap();
        let (ran, failures) = ran(
            &reload,
            &[
                "ubus call network.interface.spl_mesh down",
                "/etc/init.d/firewall reload",
            ],
        );
        assert_eq!(ran, rendered(&reload));
        assert_eq!(
            failures,
            [
                "ubus call network.interface.spl_mesh down",
                "/etc/init.d/firewall reload",
            ]
        );
    }

    #[test]
    fn network_change_without_renew_restarts_the_wireguard_interface() {
        // What `ifup` does, minus its exit code 0 for an unknown interface.
        let reload = Reload::new(&["network".to_owned()], mesh(), PeerUpdate::Restart).unwrap();
        assert_eq!(
            rendered(&reload),
            [
                "reload_config",
                "ubus call network reload",
                "ubus call network.interface.spl_mesh down",
                "ubus call network.interface.spl_mesh up",
            ]
        );
    }
}
