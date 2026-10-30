//! Applying the firewall on Linux: splot's own nft table, `inet splot`, from
//! the file splot rendered. nft checks the file before the run begins; systemd's
//! `splot-firewall`, splot's own unit, loads it, and again at every boot,
//! before the network comes up. The file replaces the table whole in one
//! transaction, so a reload never leaves a moment without it. No other table is
//! touched; the dry run warns about those that drop what they don't accept,
//! since splot's accepts get through only where they accept it too.

use std::{path::Path, process::Command};

use serde::{Deserialize, Serialize};

use splot_core::{
    consts::{NFT_FAMILY, NFT_TABLE},
    protocol::Changes,
};

use super::{
    apply::{Error, current, put_back, run, succeeds},
    file,
};
use crate::process;

/// The file the unit loads.
const PATH: &str = "/etc/splot/firewall.nft";
/// The unit that loads it, and its file.
const UNIT: &str = "splot-firewall";
const UNIT_PATH: &str = "/etc/systemd/system/splot-firewall.service";

/// The unit. A ruleset loaded with `flush ruleset` (Debian's
/// `nftables.service`) removes splot's table too, so it's loaded after that
/// one at boot, and again whenever that one is restarted or reloaded. Stopped,
/// it deletes splot's table alone.
const UNIT_TEXT: &str = "\
# splot's firewall: its own nft table, inet splot, from the file
# `splot apply` writes. Written by splot: don't edit.
[Unit]
Description=splot's firewall (nft table inet splot)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
# nftables.service flushes the whole ruleset, splot's table with it.
After=nftables.service
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=nft -f /etc/splot/firewall.nft
ExecReload=nft -f /etc/splot/firewall.nft
ExecStop=-nft delete table inet splot

[Install]
WantedBy=sysinit.target
";

/// One of the objects `nft -j list` shows: a table or a chain, among others.
#[derive(Deserialize)]
struct Object {
    table: Option<Table>,
    chain: Option<Chain>,
}

#[derive(Deserialize)]
struct Table {
    family: String,
    name: String,
}

#[derive(Deserialize)]
struct Chain {
    family: String,
    table: String,
    name: String,
    /// A base chain's: a regular chain has neither.
    hook: Option<String>,
    policy: Option<String>,
}

/// What `nft -j list` prints.
#[derive(Deserialize)]
struct Listing {
    nftables: Vec<Object>,
}

/// `nft -j list <what>`: the tables, or the chains, of every table.
fn listing(what: &str) -> Result<Vec<Object>, Error> {
    let args = ["-j", "list", what];
    let listing: Listing =
        serde_json::from_str(&run("nft", &args)?).map_err(|cause| Error::Unreadable {
            command: format!("nft {}", args.join(" ")),
            cause,
        })?;

    Ok(listing.nftables)
}

/// Whether splot's table is among `objects`.
fn loaded(objects: &[Object]) -> bool {
    objects
        .iter()
        .filter_map(|object| object.table.as_ref())
        .any(|table| table.family == NFT_FAMILY && table.name == NFT_TABLE)
}

/// A warning for each base chain of another table in `objects` that drops
/// what it doesn't accept, on a hook splot's table shares: the families that
/// see what an `inet` table does.
fn dropping(objects: &[Object]) -> Vec<String> {
    objects
        .iter()
        .filter_map(|object| object.chain.as_ref())
        .filter(|chain| (chain.family.as_str(), chain.table.as_str()) != (NFT_FAMILY, NFT_TABLE))
        .filter(|chain| ["ip", "ip6", "inet"].contains(&chain.family.as_str()))
        .filter(|chain| chain.policy.as_deref() == Some("drop"))
        .filter_map(|chain| {
            Some(format!(
                "table {} {}: chain {} drops what it doesn't accept (policy drop, hook {}), so what splot accepts on that hook gets through only where this chain accepts it too.",
                chain.family,
                chain.table,
                chain.name,
                chain.hook.as_deref()?
            ))
        })
        .collect()
}

/// The other tables that drop what they don't accept, where splot's accepts
/// need theirs: what the dry run warns about.
pub(super) fn warnings() -> Result<Vec<String>, Error> {
    Ok(dropping(&listing("chains")?))
}

/// What's live of the firewall on the node.
#[derive(Debug, Default)]
struct Live {
    /// Whether systemd runs the unit now, and starts it at boot.
    active: bool,
    enabled: bool,
    /// Whether splot's table is loaded.
    table: bool,
}

impl Live {
    fn read() -> Result<Self, Error> {
        Ok(Self {
            active: succeeds("systemctl", &["is-active", "--quiet", UNIT])?,
            enabled: succeeds("systemctl", &["is-enabled", "--quiet", UNIT])?,
            table: loaded(&listing("tables")?),
        })
    }
}

/// What systemd is to do once the files are written.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The unit's file is new or changed: systemd reads it again.
    DaemonReload,
    /// The unit isn't running: start it, which loads the table, and at every
    /// boot from now on.
    Start,
    /// The table is loaded again: the file changed, or why when it didn't.
    Reload(Option<String>),
    /// The unit runs, but wouldn't come back after a reboot.
    Enable,
}

impl Step {
    /// `systemctl`'s arguments.
    fn args(&self) -> Vec<&'static str> {
        match self {
            Self::DaemonReload => vec!["daemon-reload"],
            Self::Start => vec!["enable", "--now", UNIT],
            Self::Reload(_) => vec!["reload", UNIT],
            Self::Enable => vec!["enable", UNIT],
        }
    }

    fn run(&self) -> Result<(), Error> {
        run("systemctl", &self.args()).map(drop)
    }

    /// What it did, for apply's report; none for what only makes the rest
    /// work.
    fn done(&self) -> Option<String> {
        match self {
            Self::DaemonReload => None,
            Self::Start => Some(format!("{UNIT} started and enabled")),
            Self::Reload(_) => Some(format!("{UNIT} reloaded")),
            Self::Enable => Some(format!("{UNIT} enabled")),
        }
    }
}

/// The command, and why when a reload has a reason: what the dry run shows.
impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "systemctl {}", self.args().join(" "))?;

        if let Self::Reload(Some(why)) = self {
            write!(f, "  ({why})")?;
        }

        Ok(())
    }
}

/// What systemd is to do, given what's `live` and whether the file and the
/// unit's file change.
fn steps(live: &Live, file_changed: bool, unit_changed: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    if unit_changed {
        steps.push(Step::DaemonReload);
    }

    if !live.active {
        steps.push(Step::Start);
        return steps;
    }

    if file_changed {
        steps.push(Step::Reload(None));
    } else if !live.table {
        // Removed some other way: a `flush ruleset`, say.
        steps.push(Step::Reload(Some(format!(
            "table {NFT_FAMILY} {NFT_TABLE} isn't loaded"
        ))));
    }
    if !live.enabled {
        steps.push(Step::Enable);
    }

    steps
}

/// Has nft check `text` against what's loaded, changing nothing.
fn check(text: &str) -> Result<(), Error> {
    let mut command = Command::new("nft");
    command.args(["-c", "-f", "-"]);
    let output = process::run(command, Some(text.as_bytes())).map_err(|cause| Error::Run {
        command: "nft -c -f -".to_owned(),
        cause,
    })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::NftRefused(
            String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        ))
    }
}

/// What the node had of the firewall before a run: the file and the unit's
/// file (none: there was none), and whether the unit ran and was enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    pub(crate) file: Option<String>,
    pub(crate) unit: Option<String>,
    pub(crate) active: bool,
    pub(crate) enabled: bool,
}

/// What making `text` live would do. nft checks it first; nothing changes.
struct Planned {
    kept: Kept,
    file_changed: bool,
    unit_changed: bool,
    steps: Vec<Step>,
}

fn planned(text: &str) -> Result<Planned, Error> {
    check(text)?;

    let file = current(PATH)?;
    let unit = current(UNIT_PATH)?;
    let live = Live::read()?;
    let file_changed = file.as_deref() != Some(text);
    let unit_changed = unit.as_deref() != Some(UNIT_TEXT);

    Ok(Planned {
        steps: steps(&live, file_changed, unit_changed),
        kept: Kept {
            file,
            unit,
            active: live.active,
            enabled: live.enabled,
        },
        file_changed,
        unit_changed,
    })
}

/// What a run prepared: the files its go writes, if they change, and what
/// systemd does after.
pub(super) struct Prepared {
    /// The file; none when it doesn't change.
    text: Option<String>,
    unit_changed: bool,
    steps: Vec<Step>,
    /// What the go changes, as the dry run shows it.
    pub(super) changes: Changes,
    /// What the node has, for the run to put back.
    pub(super) kept: Kept,
}

/// Works out what writing `text` and loading it changes, once nft has checked
/// it, changing nothing yet: none when nothing does.
pub(super) fn prepare(text: &str) -> Result<Option<Prepared>, Error> {
    let planned = planned(text)?;
    if planned.steps.is_empty() {
        return Ok(None);
    }

    Ok(Some(Prepared {
        text: planned.file_changed.then(|| text.to_owned()),
        unit_changed: planned.unit_changed,
        changes: described(text, &planned),
        steps: planned.steps,
        kept: planned.kept,
    }))
}

/// Applies what was prepared: writes the files, then has systemd load the
/// table.
pub(super) fn go(prepared: &Prepared) -> Result<(), Error> {
    if prepared.unit_changed {
        file::write_public(Path::new(UNIT_PATH), UNIT_TEXT)
            .map_err(|err| Error::Write(UNIT_PATH, err))?;
    }
    if let Some(text) = &prepared.text {
        file::write_private(Path::new(PATH), text).map_err(|err| Error::Write(PATH, err))?;
    }
    for step in &prepared.steps {
        step.run()?;
    }

    Ok(())
}

/// Puts back the files a run changed as they were, and the unit running and
/// enabled as it was, its table loaded from the file it had.
pub(super) fn restore(kept: &Kept) -> Result<(), Error> {
    // While the unit is still the one that loaded the table: stopping it
    // deletes the table.
    if !kept.active && succeeds("systemctl", &["is-active", "--quiet", UNIT])? {
        run("systemctl", &["stop", UNIT])?;
    }
    if !kept.enabled && succeeds("systemctl", &["is-enabled", "--quiet", UNIT])? {
        run("systemctl", &["disable", UNIT])?;
    }

    put_back(PATH, kept.file.as_deref(), file::write_private)?;
    if current(UNIT_PATH)? != kept.unit {
        put_back(UNIT_PATH, kept.unit.as_deref(), file::write_public)?;
        run("systemctl", &["daemon-reload"])?;
    }

    if kept.active {
        run("systemctl", &["reload-or-restart", UNIT])?;
    }
    if kept.enabled {
        run("systemctl", &["enable", UNIT])?;
    }

    Ok(())
}

/// What `go` would do: the files, if they change, and the systemd steps
/// after.
pub(super) fn print(text: &str) -> Result<Changes, Error> {
    Ok(described(text, &planned(text)?))
}

/// What writing the files (when they change) and the steps change: in a few
/// words, as the go reports it, and as the dry run shows it.
fn described(text: &str, planned: &Planned) -> Changes {
    if planned.steps.is_empty() {
        return Changes::none();
    }

    let mut shown = String::new();
    if planned.file_changed {
        shown.push_str(&format!("# {PATH} becomes:\n{text}"));
    }
    if planned.unit_changed {
        shown.push_str(&format!("# {UNIT_PATH} becomes:\n{UNIT_TEXT}"));
    }
    shown.push_str("# Then splot runs:\n");
    for step in &planned.steps {
        shown.push_str(&format!("#   {step}\n"));
    }

    Changes {
        summary: [
            planned.file_changed.then(|| PATH.to_owned()),
            planned.unit_changed.then(|| UNIT_PATH.to_owned()),
        ]
        .into_iter()
        .flatten()
        .chain(planned.steps.iter().filter_map(Step::done))
        .collect(),
        text: shown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects(json: &str) -> Vec<Object> {
        serde_json::from_str::<Listing>(json).unwrap().nftables
    }

    fn live(active: bool, enabled: bool, table: bool) -> Live {
        Live {
            active,
            enabled,
            table,
        }
    }

    fn steps_for(live: &Live, file_changed: bool, unit_changed: bool) -> Vec<String> {
        steps(live, file_changed, unit_changed)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_unit_that_isnt_running_is_started_and_enabled_once_systemd_has_read_it() {
        assert_eq!(
            steps_for(&Live::default(), true, true),
            [
                "systemctl daemon-reload",
                "systemctl enable --now splot-firewall"
            ]
        );
        // Started whatever the files: starting loads the table.
        for (file_changed, table) in [(false, false), (false, true), (true, true)] {
            assert_eq!(
                steps_for(&live(false, false, table), file_changed, false),
                ["systemctl enable --now splot-firewall"]
            );
        }
    }

    #[test]
    fn a_changed_file_is_loaded_again() {
        assert_eq!(
            steps_for(&live(true, true, true), true, false),
            ["systemctl reload splot-firewall"]
        );
        // And with a changed unit, once systemd has read it.
        assert_eq!(
            steps_for(&live(true, true, true), true, true),
            ["systemctl daemon-reload", "systemctl reload splot-firewall"]
        );
    }

    #[test]
    fn a_table_removed_some_other_way_is_loaded_again_saying_why() {
        assert_eq!(
            steps_for(&live(true, true, false), false, false),
            ["systemctl reload splot-firewall  (table inet splot isn't loaded)"]
        );
        // A changed file is reason enough.
        assert_eq!(
            steps_for(&live(true, true, false), true, false),
            ["systemctl reload splot-firewall"]
        );
    }

    #[test]
    fn nothing_changes_when_the_files_are_the_same_and_the_table_is_loaded() {
        assert!(steps_for(&live(true, true, true), false, false).is_empty());
        // A changed unit alone only needs systemd to read it.
        assert_eq!(
            steps_for(&live(true, true, true), false, true),
            ["systemctl daemon-reload"]
        );
    }

    #[test]
    fn a_unit_that_wouldnt_come_back_after_a_reboot_is_enabled() {
        assert_eq!(
            steps_for(&live(true, false, true), false, false),
            ["systemctl enable splot-firewall"]
        );
        assert_eq!(
            steps_for(&live(true, false, true), true, false),
            [
                "systemctl reload splot-firewall",
                "systemctl enable splot-firewall"
            ]
        );
    }

    #[test]
    fn splots_table_is_found_among_the_loaded_ones_by_family_and_name() {
        let tables = |tables: &str| {
            loaded(&objects(&format!(
                r#"{{"nftables": [{{"metainfo": {{"version": "1.1.3", "json_schema_version": 1}}}}{tables}]}}"#
            )))
        };
        assert!(tables(
            r#", {"table": {"family": "ip", "name": "filter", "handle": 1}}, {"table": {"family": "inet", "name": "splot", "handle": 2}}"#
        ));
        assert!(!tables(""));
        // Another family's table of the same name isn't splot's.
        assert!(!tables(
            r#", {"table": {"family": "ip", "name": "splot", "handle": 1}}"#
        ));
        assert!(!tables(
            r#", {"table": {"family": "inet", "name": "filter", "handle": 1}}"#
        ));
    }

    #[test]
    fn other_tables_base_chains_that_drop_by_default_are_warned_about() {
        let json = r#"{"nftables": [
            {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 2}},
            {"chain": {"family": "inet", "table": "host", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "inet", "table": "host", "name": "output", "handle": 2, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
            {"chain": {"family": "ip6", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "bridge", "table": "filter", "name": "forward", "handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "netdev", "table": "edge", "name": "ingress", "handle": 1, "type": "filter", "hook": "ingress", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "inet", "table": "splot", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}
        ]}"#;
        assert_eq!(
            dropping(&objects(json)),
            [
                "table ip filter: chain FORWARD drops what it doesn't accept (policy drop, hook forward), so what splot accepts on that hook gets through only where this chain accepts it too.",
                "table inet host: chain input drops what it doesn't accept (policy drop, hook input), so what splot accepts on that hook gets through only where this chain accepts it too.",
                "table ip6 filter: chain INPUT drops what it doesn't accept (policy drop, hook input), so what splot accepts on that hook gets through only where this chain accepts it too.",
            ]
        );
    }

    #[test]
    fn the_dry_run_shows_the_files_that_change_and_what_systemd_does() {
        let text = "table inet splot\n";
        let kept = Kept {
            file: None,
            unit: None,
            active: false,
            enabled: false,
        };
        let changes = described(
            text,
            &Planned {
                kept: kept.clone(),
                file_changed: true,
                unit_changed: true,
                steps: steps(&Live::default(), true, true),
            },
        );
        assert_eq!(
            changes.summary,
            [
                "/etc/splot/firewall.nft",
                "/etc/systemd/system/splot-firewall.service",
                "splot-firewall started and enabled"
            ]
        );
        assert_eq!(
            changes.text,
            format!(
                "# /etc/splot/firewall.nft becomes:\ntable inet splot\n# /etc/systemd/system/splot-firewall.service becomes:\n{UNIT_TEXT}# Then splot runs:\n#   systemctl daemon-reload\n#   systemctl enable --now splot-firewall\n"
            )
        );

        // The file alone.
        let changes = described(
            text,
            &Planned {
                kept: kept.clone(),
                file_changed: true,
                unit_changed: false,
                steps: steps(&live(true, true, true), true, false),
            },
        );
        assert_eq!(
            changes.summary,
            ["/etc/splot/firewall.nft", "splot-firewall reloaded"]
        );
        assert!(!changes.text.contains(UNIT_PATH));

        // Nothing.
        let nothing = described(
            text,
            &Planned {
                kept,
                file_changed: false,
                unit_changed: false,
                steps: Vec::new(),
            },
        );
        assert_eq!(nothing, Changes::none());
    }

    #[test]
    fn the_unit_loads_splots_file_and_stopping_it_deletes_only_splots_table() {
        let table = format!("{NFT_FAMILY} {NFT_TABLE}");
        assert!(UNIT_TEXT.contains(&format!("\nExecStart=nft -f {PATH}\n")));
        assert!(UNIT_TEXT.contains(&format!("\nExecReload=nft -f {PATH}\n")));
        assert!(UNIT_TEXT.contains(&format!("\nExecStop=-nft delete table {table}\n")));
        // Nothing it runs touches another table.
        assert!(
            UNIT_TEXT
                .lines()
                .filter(|line| line.starts_with("Exec"))
                .all(|line| line.ends_with(PATH) || line.ends_with(&table))
        );
        assert!(UNIT_PATH.ends_with(&format!("/{UNIT}.service")));
    }
}
