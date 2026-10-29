//! Applying the rendered config on Linux: write the wg-quick file, then have
//! systemd's `wg-quick@spl_mesh` make it live. It's started if it isn't running,
//! and enabled so it comes back after a reboot. wg-quick sets the interface's
//! address and routes only when it starts, so it's restarted when what's live
//! differs from what the file makes; otherwise it's reloaded, which is
//! `wg syncconf`: the tunnels stay up. splot never sets an address or a route
//! itself, so what's live is always wg-quick's own.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io, iter,
    path::Path,
    process::{Command, Output},
};

use serde::{Deserialize, de::DeserializeOwned};

use splot_core::protocol::{Changes, Run, linux::WgQuickConfig};

use super::{INTERFACE, file};
use crate::{
    node::NotConfirmed,
    process,
    run::{self, Backup},
    secret::MissingPsks,
    wg,
};

/// The file wg-quick reads for the interface.
pub(super) const PATH: &str = "/etc/wireguard/spl_mesh.conf";
/// The systemd unit that runs wg-quick for it.
const UNIT: &str = "wg-quick@spl_mesh";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    NotConfirmed(#[from] NotConfirmed),
    #[error(transparent)]
    RunState(#[from] run::Error),
    #[error("can't drop the WireGuard session of a peer whose preshared key changed")]
    FreshSession(#[source] crate::wg::Error),
    #[error("applying failed, so this peer put back what it had")]
    PutBack(#[source] Box<Error>),
    #[error(
        "applying failed, and putting back what this peer had failed too ({rollback}) - check it"
    )]
    NotPutBack {
        #[source]
        cause: Box<Error>,
        rollback: run::Error,
    },
    #[error(transparent)]
    MissingPsks(#[from] MissingPsks),
    #[error("can't read {PATH}")]
    Read(#[source] io::Error),
    #[error("can't write {PATH}")]
    Write(#[source] io::Error),
    #[error("failed to run `{command}`")]
    Run {
        command: String,
        #[source]
        cause: process::Error,
    },
    #[error("`{command}` failed (exit code {code:?}): {stderr}")]
    Failed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("`{command}` printed what splot can't read")]
    Unreadable {
        command: String,
        #[source]
        cause: serde_json::Error,
    },
    #[error(
        "{INTERFACE} is up, but not through {UNIT}, which splot runs it with - bring it down (`wg-quick down {INTERFACE}`, if that's how it came up) and apply again"
    )]
    NotTheUnits,
}

/// `program args`, as an error message shows it.
fn shown(program: &str, args: &[&str]) -> String {
    iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

fn output(program: &str, args: &[&str]) -> Result<Output, Error> {
    let mut command = Command::new(program);
    command.args(args);

    process::run(command, None).map_err(|cause| Error::Run {
        command: shown(program, args),
        cause,
    })
}

/// Runs `program args` and returns what it printed; an error carrying what it
/// said when it fails.
fn run(program: &str, args: &[&str]) -> Result<String, Error> {
    let output = output(program, args)?;

    if !output.status.success() {
        return Err(Error::Failed {
            command: shown(program, args),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether `program args` exits 0: how `systemctl is-active` and `is-enabled`
/// answer.
fn succeeds(program: &str, args: &[&str]) -> Result<bool, Error> {
    Ok(output(program, args)?.status.success())
}

/// An address on the interface, as `ip -j address` shows it.
#[derive(Deserialize)]
struct IpAddress {
    family: Option<String>,
    local: Option<String>,
    prefixlen: Option<u8>,
}

#[derive(Deserialize)]
struct IpLink {
    #[serde(default)]
    addr_info: Vec<IpAddress>,
}

/// A route, as `ip -j route` shows it.
#[derive(Deserialize)]
struct IpRoute {
    dst: String,
    protocol: Option<String>,
}

/// `ip -j`'s output: a list, or nothing at all from some versions when there's
/// nothing to show.
fn parse_json<T: DeserializeOwned>(output: &str, command: &str) -> Result<Vec<T>, Error> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(output).map_err(|cause| Error::Unreadable {
        command: command.to_owned(),
        cause,
    })
}

/// `ip -j -4 <what> show dev spl_mesh`, read as a list.
fn ip<T: DeserializeOwned>(what: &str) -> Result<Vec<T>, Error> {
    let args = ["-j", "-4", what, "show", "dev", INTERFACE];
    parse_json(&run("ip", &args)?, &shown("ip", &args))
}

/// The interface's IPv4 addresses in `ip -j -4 address show dev` output, as
/// `10.100.0.4/16`.
fn addresses(links: Vec<IpLink>) -> Vec<String> {
    links
        .into_iter()
        .flat_map(|link| link.addr_info)
        .filter(|address| {
            address
                .family
                .as_deref()
                .is_none_or(|family| family == "inet")
        })
        .filter_map(|address| Some(format!("{}/{}", address.local?, address.prefixlen?)))
        .collect()
}

/// The routes in `ip -j -4 route show dev` output, as `192.168.2.0/24`, except
/// the kernel's own for the interface's address: wg-quick's are the rest.
fn routes(routes: Vec<IpRoute>) -> BTreeSet<String> {
    routes
        .into_iter()
        .filter(|route| route.protocol.as_deref() != Some("kernel"))
        .map(|route| match route.dst.as_str() {
            "default" => "0.0.0.0/0".to_owned(),
            // A host route is shown without its prefix.
            dst if !dst.contains('/') => format!("{dst}/32"),
            dst => dst.to_owned(),
        })
        .collect()
}

/// The interface, when it's there: its addresses and the routes through it.
#[derive(Debug, Default)]
struct Interface {
    addresses: Vec<String>,
    routes: BTreeSet<String>,
}

/// What's live of the mesh on the node.
#[derive(Debug, Default)]
struct Live {
    /// Whether systemd runs the unit now, and starts it at boot.
    active: bool,
    enabled: bool,
    interface: Option<Interface>,
}

impl Live {
    fn read() -> Result<Self, Error> {
        let interface = if Path::new("/sys/class/net").join(INTERFACE).exists() {
            Some(Interface {
                addresses: addresses(ip("address")?),
                routes: routes(ip("route")?),
            })
        } else {
            None
        };

        Ok(Self {
            active: succeeds("systemctl", &["is-active", "--quiet", UNIT])?,
            enabled: succeeds("systemctl", &["is-enabled", "--quiet", UNIT])?,
            interface,
        })
    }
}

/// What systemd is to do once the file is written.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The unit isn't running: start it, and at every boot from now on.
    Start,
    /// What only a start sets differs from what the file makes: why.
    Restart(Vec<String>),
    /// The file changed, and only in what `wg syncconf` applies live.
    Reload,
    /// The unit runs, but wouldn't come back after a reboot.
    Enable,
}

impl Step {
    /// `systemctl`'s arguments.
    fn args(&self) -> Vec<&'static str> {
        match self {
            Self::Start => vec!["enable", "--now", UNIT],
            Self::Restart(_) => vec!["restart", UNIT],
            Self::Reload => vec!["reload", UNIT],
            Self::Enable => vec!["enable", UNIT],
        }
    }

    fn run(&self) -> Result<(), Error> {
        run("systemctl", &self.args()).map(drop)
    }

    /// What it did, for apply's report.
    fn done(&self) -> String {
        match self {
            Self::Start => format!("{UNIT} started and enabled"),
            Self::Restart(why) => format!("{UNIT} restarted ({})", why.join("; ")),
            Self::Reload => format!("{UNIT} reloaded"),
            Self::Enable => format!("{UNIT} enabled"),
        }
    }
}

/// The command, and why when it's a restart: what the dry run shows.
impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "systemctl {}", self.args().join(" "))?;

        if let Self::Restart(why) = self {
            write!(f, "  ({})", why.join("; "))?;
        }

        Ok(())
    }
}

/// Where what's live differs from what wg-quick would set from `config`, in
/// what only a start sets.
fn differences(interface: &Interface, config: &WgQuickConfig) -> Vec<String> {
    let mut differences = Vec::new();

    let address = config.address.to_string();
    if interface.addresses != [address.clone()] {
        let live = if interface.addresses.is_empty() {
            "none".to_owned()
        } else {
            interface.addresses.join(", ")
        };
        differences.push(format!("its address is {live}, the config's {address}"));
    }

    let wanted: BTreeSet<String> = config.routes.iter().map(ToString::to_string).collect();
    let missing: Vec<&str> = wanted
        .difference(&interface.routes)
        .map(String::as_str)
        .collect();
    let stale: Vec<&str> = interface
        .routes
        .difference(&wanted)
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        differences.push(format!("routes to add: {}", missing.join(", ")));
    }
    if !stale.is_empty() {
        differences.push(format!("routes to remove: {}", stale.join(", ")));
    }

    differences
}

/// What systemd is to do, given what's `live` and whether the file changes.
fn steps(live: &Live, config: &WgQuickConfig, file_changed: bool) -> Result<Vec<Step>, Error> {
    if !live.active {
        // Started, wg-quick would fail on the interface that's there.
        return match live.interface {
            Some(_) => Err(Error::NotTheUnits),
            None => Ok(vec![Step::Start]),
        };
    }

    let differences = match &live.interface {
        Some(interface) => differences(interface, config),
        None => vec![format!("{INTERFACE} isn't there")],
    };

    let mut steps = Vec::new();
    if !differences.is_empty() {
        steps.push(Step::Restart(differences));
    } else if file_changed {
        steps.push(Step::Reload);
    }
    if !live.enabled {
        steps.push(Step::Enable);
    }

    Ok(steps)
}

/// The file as it is now; none if there's none yet.
fn current() -> Result<Option<String>, Error> {
    match fs::read_to_string(PATH) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Read(err)),
    }
}

/// What `run` would do: whether the file changes, and the steps after it;
/// and what's live now. Reads only.
fn changes(config: &WgQuickConfig, text: &str) -> Result<(bool, Vec<Step>, Live), Error> {
    let file_changed = current()?.as_deref() != Some(text);
    let live = Live::read()?;
    let steps = steps(&live, config, file_changed)?;

    Ok((file_changed, steps, live))
}

/// What a run prepared: the file its go writes, if it changes, and what
/// systemd does after.
pub struct Prepared {
    /// The file with its secrets in; none when it doesn't change.
    text: Option<String>,
    /// The peers whose sessions go before a reload: their preshared key
    /// changed.
    fresh: Vec<String>,
    steps: Vec<Step>,
    changes: Changes,
}

impl Prepared {
    /// Nothing to do.
    pub(crate) fn nothing() -> Self {
        Self {
            text: None,
            fresh: Vec::new(),
            steps: Vec::new(),
            changes: Changes::none(),
        }
    }

    /// What the go changes, as the dry run shows it.
    pub fn changes(&self) -> &Changes {
        &self.changes
    }
}

/// Begins `run` to write `text`, the file with its secrets in, and make it
/// live, changing nothing yet: works out whether the file changes and what
/// systemd does after, and keeps what the node has for the run.
pub(super) fn prepare(config: &WgQuickConfig, text: &str, run: &Run) -> Result<Prepared, Error> {
    let (file_changed, steps, live) = changes(config, text)?;
    if !file_changed && steps.is_empty() {
        run::begin(run, INTERFACE, None)?;
        return Ok(Prepared::nothing());
    }

    let before = current()?;
    // A reload keeps the sessions it has: a peer whose preshared key changed
    // gets a fresh one. A start or a restart has none to keep.
    let fresh = if steps.contains(&Step::Reload) {
        psk_changed(before.as_deref().unwrap_or_default(), text)
    } else {
        Vec::new()
    };
    let backup = Backup::Linux {
        file: before,
        active: live.active,
        enabled: live.enabled,
    };
    run::begin(run, INTERFACE, Some(backup))?;

    Ok(Prepared {
        text: file_changed.then(|| text.to_owned()),
        fresh,
        changes: described(config, file_changed, &steps),
        steps,
    })
}

/// Applies what run `id` prepared: writes the file, then has systemd make it
/// live. When any of it fails, puts back what the node had. Returns what
/// changed.
pub(super) fn go(prepared: &Prepared, id: &str) -> Result<Vec<String>, Error> {
    run::go(id)?;

    let applied = (|| {
        if let Some(text) = &prepared.text {
            file::write_private(Path::new(PATH), text).map_err(Error::Write)?;
        }
        for key in &prepared.fresh {
            wg::remove_peer(INTERFACE, key).map_err(Error::FreshSession)?;
        }
        for step in &prepared.steps {
            step.run()?;
        }
        Ok(())
    })();
    if let Err(cause) = applied {
        let cause = Box::new(cause);
        return Err(match run::rollback(id) {
            Ok(()) => Error::PutBack(cause),
            Err(rollback) => Error::NotPutBack { cause, rollback },
        });
    }

    Ok(prepared.changes.summary.clone())
}

/// Each peer's public key in a wg-quick file, and its pair's preshared key.
fn psks(file: &str) -> BTreeMap<&str, Option<&str>> {
    let mut psks = BTreeMap::new();
    let mut peer: Option<&str> = None;

    for line in file.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            peer = None;
        } else if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "PublicKey" => {
                    peer = Some(value.trim());
                    psks.entry(value.trim()).or_insert(None);
                }
                "PresharedKey" => {
                    if let Some(peer) = peer {
                        psks.insert(peer, Some(value.trim()));
                    }
                }
                _ => {}
            }
        }
    }

    psks
}

/// The public keys of the peers in both files whose preshared key differs
/// (set, changed or removed): WireGuard keeps a session it has until its next
/// rekey, so these need a fresh one for the new key to be the one checked.
fn psk_changed(before: &str, after: &str) -> Vec<String> {
    let before = psks(before);
    psks(after)
        .into_iter()
        .filter(|(peer, psk)| before.get(peer).is_some_and(|old| old != psk))
        .map(|(peer, _)| peer.to_owned())
        .collect()
}

/// Puts back the wg-quick file a run changed as it was (`file`: none for one
/// there wasn't), and its unit running and enabled as it was.
pub(super) fn restore(file: Option<&str>, active: bool, enabled: bool) -> Result<(), Error> {
    match file {
        Some(text) => file::write_private(Path::new(PATH), text).map_err(Error::Write)?,
        None => match fs::remove_file(PATH) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(Error::Write(err)),
            _ => {}
        },
    }

    run(
        "systemctl",
        &[if active { "restart" } else { "stop" }, UNIT],
    )?;
    run(
        "systemctl",
        &[if enabled { "enable" } else { "disable" }, UNIT],
    )?;

    Ok(())
}

/// What `go` would do: the file, if it changes, and the systemd steps after
/// it.
pub(super) fn print(config: &WgQuickConfig, text: &str) -> Result<Changes, Error> {
    let (file_changed, steps, _) = changes(config, text)?;

    Ok(described(config, file_changed, &steps))
}

/// What writing the file (when it changes) and `steps` change: in a few words,
/// as the go reports it, and as the dry run shows it, the file's secrets as
/// their placeholders.
fn described(config: &WgQuickConfig, file_changed: bool, steps: &[Step]) -> Changes {
    if !file_changed && steps.is_empty() {
        return Changes::none();
    }

    let mut shown = String::new();
    if file_changed {
        shown.push_str(&format!("# {PATH} becomes:\n"));
        shown.push_str(&config.masked());
    }
    if !steps.is_empty() {
        shown.push_str("# Then splot runs:\n");
        for step in steps {
            shown.push_str(&format!("#   {step}\n"));
        }
    }

    Changes {
        summary: file_changed
            .then(|| PATH.to_owned())
            .into_iter()
            .chain(steps.iter().map(Step::done))
            .collect(),
        text: shown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Home's config: address 10.100.0.1/16, routes to Cabin's two zones.
    fn config() -> WgQuickConfig {
        WgQuickConfig {
            lines: Vec::new(),
            address: "10.100.0.1/16".to_owned(),
            routes: ["192.168.2.0/24", "192.168.3.0/24"]
                .map(str::to_owned)
                .into(),
        }
    }

    /// The unit running, enabled, with the interface as wg-quick set it up.
    fn up(addresses: &[&str], routes: &[&str]) -> Live {
        Live {
            active: true,
            enabled: true,
            interface: Some(Interface {
                addresses: addresses.iter().map(|a| a.to_string()).collect(),
                routes: routes.iter().map(|r| r.to_string()).collect(),
            }),
        }
    }

    fn as_wg_quick_set_it() -> Live {
        up(&["10.100.0.1/16"], &["192.168.2.0/24", "192.168.3.0/24"])
    }

    fn steps_for(live: &Live, file_changed: bool) -> Vec<String> {
        steps(live, &config(), file_changed)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_peer_whose_preshared_key_changed_gets_a_fresh_session() {
        let file = |cabin: &str, lake: &str| {
            format!(
                "[Interface]
PrivateKey = RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=

# Cabin
[Peer]
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
{cabin}AllowedIPs = 10.100.0.2/32

# Lake
[Peer]
PublicKey = LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLA=
{lake}AllowedIPs = 10.100.0.3/32
"
            )
        };
        let psk = |key: char| format!("PresharedKey = {}A=\n", key.to_string().repeat(42));
        let cabin = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
        let lake = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLA=";

        // Changed; set; removed: each one. The other peer's stays.
        assert_eq!(
            psk_changed(&file(&psk('S'), &psk('T')), &file(&psk('U'), &psk('T'))),
            [cabin]
        );
        assert_eq!(
            psk_changed(&file("", &psk('T')), &file(&psk('U'), &psk('T'))),
            [cabin]
        );
        assert_eq!(
            psk_changed(&file(&psk('S'), &psk('T')), &file(&psk('S'), "")),
            [lake]
        );
        // The same file; a new peer (no session to keep); no file before.
        assert!(psk_changed(&file(&psk('S'), &psk('T')), &file(&psk('S'), &psk('T'))).is_empty());
        let without_lake = &file(&psk('S'), "")[..file(&psk('S'), "").find("# Lake").unwrap()];
        assert!(psk_changed(without_lake, &file(&psk('S'), &psk('T'))).is_empty());
        assert!(psk_changed("", &file(&psk('S'), &psk('T'))).is_empty());
    }

    #[test]
    fn a_unit_that_isnt_running_is_started_and_enabled() {
        for file_changed in [true, false] {
            assert_eq!(
                steps_for(&Live::default(), file_changed),
                ["systemctl enable --now wg-quick@spl_mesh"]
            );
        }
    }

    #[test]
    fn an_interface_up_some_other_way_is_refused() {
        let live = Live {
            active: false,
            ..as_wg_quick_set_it()
        };
        assert!(matches!(
            steps(&live, &config(), true),
            Err(Error::NotTheUnits)
        ));
    }

    #[test]
    fn a_change_to_wireguard_alone_is_a_reload() {
        assert_eq!(
            steps_for(&as_wg_quick_set_it(), true),
            ["systemctl reload wg-quick@spl_mesh"]
        );
        // Nothing to do when the file is what's there.
        assert!(steps_for(&as_wg_quick_set_it(), false).is_empty());
    }

    #[test]
    fn a_change_to_the_routes_or_the_address_is_a_restart_saying_why() {
        // Whether the file changes or not: what's live is what counts.
        for file_changed in [true, false] {
            assert_eq!(
                steps_for(&up(&["10.100.0.1/16"], &["192.168.2.0/24"]), file_changed),
                ["systemctl restart wg-quick@spl_mesh  (routes to add: 192.168.3.0/24)"]
            );
        }
        assert_eq!(
            steps_for(
                &up(
                    &["10.100.0.1/16"],
                    &["192.168.2.0/24", "192.168.3.0/24", "192.168.9.0/24"]
                ),
                false
            ),
            ["systemctl restart wg-quick@spl_mesh  (routes to remove: 192.168.9.0/24)"]
        );
        assert_eq!(
            steps_for(&up(&["10.100.0.9/16"], &["192.168.3.0/24"]), true),
            [
                "systemctl restart wg-quick@spl_mesh  (its address is 10.100.0.9/16, the config's 10.100.0.1/16; routes to add: 192.168.2.0/24)"
            ]
        );
        assert_eq!(
            steps_for(&up(&[], &["192.168.2.0/24", "192.168.3.0/24"]), false),
            [
                "systemctl restart wg-quick@spl_mesh  (its address is none, the config's 10.100.0.1/16)"
            ]
        );
        // The unit runs, but its interface is gone.
        let gone = Live {
            interface: None,
            ..as_wg_quick_set_it()
        };
        assert_eq!(
            steps_for(&gone, false),
            ["systemctl restart wg-quick@spl_mesh  (spl_mesh isn't there)"]
        );
    }

    #[test]
    fn a_unit_that_wouldnt_come_back_after_a_reboot_is_enabled() {
        let live = Live {
            enabled: false,
            ..as_wg_quick_set_it()
        };
        assert_eq!(
            steps_for(&live, false),
            ["systemctl enable wg-quick@spl_mesh"]
        );
        assert_eq!(
            steps_for(&live, true),
            [
                "systemctl reload wg-quick@spl_mesh",
                "systemctl enable wg-quick@spl_mesh"
            ]
        );
    }

    #[test]
    fn what_ip_shows_is_read_as_the_interfaces_addresses_and_wg_quicks_routes() {
        let links = r#"[{"ifindex":5,"ifname":"spl_mesh","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1420,"addr_info":[{"family":"inet","local":"10.100.0.1","prefixlen":16,"scope":"global","label":"spl_mesh"}]}]"#;
        assert_eq!(
            addresses(parse_json(links, "ip").unwrap()),
            ["10.100.0.1/16"]
        );
        // An interface without an IPv4 address.
        assert!(addresses(parse_json(r#"[{}]"#, "ip").unwrap()).is_empty());

        let routes_json = r#"[{"dst":"10.100.0.0/16","protocol":"kernel","scope":"link","prefsrc":"10.100.0.1","flags":[]},{"dst":"192.168.2.0/24","scope":"link","flags":[]},{"dst":"10.9.9.9","scope":"link","flags":[]},{"dst":"default","scope":"link","flags":[]}]"#;
        let read = routes(parse_json(routes_json, "ip").unwrap());
        assert_eq!(
            read.into_iter().collect::<Vec<_>>(),
            ["0.0.0.0/0", "10.9.9.9/32", "192.168.2.0/24"]
        );

        // Nothing to show, either way.
        assert!(routes(parse_json("", "ip").unwrap()).is_empty());
        assert!(routes(parse_json("[]\n", "ip").unwrap()).is_empty());
        assert!(matches!(
            parse_json::<IpRoute>("Device \"x\" does not exist.", "ip route"),
            Err(Error::Unreadable { .. })
        ));
    }
}
