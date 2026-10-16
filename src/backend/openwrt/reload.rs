//! Making committed config live on OpenWrt. `uci commit` only writes files: the
//! services keep running the old config until something reloads them.
//!
//! Every command here is a request to a system daemon (procd, netifd) and returns
//! at once; the daemons restart things afterwards, independently of splot's
//! session. So a reload that briefly drops the mesh can't cut splot off halfway.

use std::{
    fmt::{self, Display},
    process::{Command, Stdio},
};

use log::info;

use super::network;

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
}

impl Reload {
    /// `None` when no file changed.
    pub fn new(
        changed_files: &[&str],
        wireguard_interface: String,
        peer_update: PeerUpdate,
    ) -> Option<Self> {
        if changed_files.is_empty() {
            return None;
        }

        Some(Self {
            wireguard_interface: changed_files
                .contains(&network::FILE)
                .then_some(wireguard_interface),
            peer_update,
        })
    }

    /// The commands, in order.
    pub fn commands(&self) -> Vec<ReloadCommand> {
        // Reloads every service whose config changed since its last run: fw4 for
        // `firewall`, dnsmasq for `dhcp`, netifd for interface-level changes.
        // procd runs those reloads a second later.
        let mut commands = vec![ReloadCommand::new("reload_config", &[])];

        let Some(interface) = &self.wireguard_interface else {
            return commands;
        };

        // netifd re-reads the config now, so the peer update below reaches the
        // interface even when it's new in this commit.
        commands.push(ReloadCommand::ubus(&["call", "network", "reload"]));

        let object = format!("network.interface.{interface}");
        match self.peer_update {
            PeerUpdate::Renew => {
                commands.push(ReloadCommand::ubus(&["call", &object, "renew"]));
            }
            PeerUpdate::Restart => {
                commands.push(ReloadCommand::ubus(&["call", &object, "down"]));
                commands.push(ReloadCommand::ubus(&["call", &object, "up"]));
            }
        }

        commands
    }

    /// Runs every command, even after one failed, and reports all failures.
    pub fn run(&self) -> Result<(), Error> {
        let failures: Vec<Error> = self
            .commands()
            .iter()
            .filter_map(|command| {
                info!("Running `{command}`");
                run(command).err()
            })
            .collect();

        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::Reload(failures))
        }
    }
}

/// Runs `command` and returns its stdout. A non-zero exit is an error.
fn run(command: &ReloadCommand) -> Result<String, Error> {
    let output = Command::new(command.program)
        .args(&command.args)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| Error::Spawn(command.program, err))?;

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
        let reload = Reload::new(&["firewall"], mesh(), PeerUpdate::Restart).unwrap();
        assert_eq!(rendered(&reload), ["reload_config"]);
    }

    #[test]
    fn network_change_renews_the_wireguard_interface() {
        // netifd re-reads the config first (procd would only do it a second
        // later): a renew can't reach an interface netifd doesn't know yet.
        let reload = Reload::new(&["network", "dhcp"], mesh(), PeerUpdate::Renew).unwrap();
        assert_eq!(
            rendered(&reload),
            [
                "reload_config",
                "ubus call network reload",
                "ubus call network.interface.spl_mesh renew",
            ]
        );
    }

    #[test]
    fn network_change_without_renew_restarts_the_wireguard_interface() {
        // What `ifup` does, minus its exit code 0 for an unknown interface.
        let reload = Reload::new(&["network"], mesh(), PeerUpdate::Restart).unwrap();
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
