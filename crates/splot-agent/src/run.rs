//! A run: a change applied on this node that the node puts back by itself
//! unless splot confirms it in time. What it needs lives in files under `DIR`,
//! so it outlasts the session that started it, and a process of its own (the
//! agent, started again: `watch`) keeps the deadline.
//!
//! The outcome is decided once: whoever renames `ARMED` first. A confirm turns
//! it into `CONFIRMED`; a rollback, asked for or at the deadline, into
//! `ROLLING_BACK`, and puts back what the node had.

use std::{
    env, fs,
    io::{self, ErrorKind},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use splot_core::protocol::{Probe, Run};

use crate::{linux, openwrt, probe};

/// Where the run lives: in RAM on a router, gone at a reboot. Beside it,
/// `last` says how the last run ended, for whoever asks after it.
pub const DIR: &str = "/tmp/splot/run";
/// Set on the process that keeps a run's deadline: the run's directory.
pub const WATCHDOG: &str = "SPLOT_WATCHDOG";

const INFO: &str = "info.json";
const ARMED: &str = "armed";
const CONFIRMED: &str = "confirmed";
const ROLLING_BACK: &str = "rolling-back";

/// What the node had before the run, to put back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backup {
    /// uci files, each with what it held (none: there was none).
    OpenWrt {
        files: Vec<(PathBuf, Option<String>)>,
    },
    /// The wg-quick file (none: there was none), and whether its unit ran and
    /// was enabled.
    Linux {
        file: Option<String>,
        active: bool,
        enabled: bool,
    },
}

impl Backup {
    /// Puts it back, and makes it live.
    fn restore(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::OpenWrt { files } => openwrt::restore(files)?,
            Self::Linux {
                file,
                active,
                enabled,
            } => linux::restore(file.as_deref(), *active, *enabled)?,
        }

        Ok(())
    }
}

/// What a run's directory says about it. It holds the backup, so only root may
/// read it.
#[derive(Debug, Serialize, Deserialize)]
struct Info {
    id: String,
    /// Seconds since the epoch: when the node puts back what it had.
    deadline: u64,
    backup: Backup,
    /// The node's peers that answered when the run began: they must after.
    answered: Vec<Probe>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "another run is in progress on this peer ({other}): it ends when it's confirmed, or at its deadline"
    )]
    Busy { other: String },
    #[error("this peer has no run {id}: it ended, or never began")]
    NoSuchRun { id: String },
    #[error("too late: this peer has put back what it had before run {id}")]
    TooLate { id: String },
    #[error("can't keep the run's state in {}", DIR)]
    Io(#[from] io::Error),
    #[error("the run's state in {} can't be read", DIR)]
    Unreadable(#[from] serde_json::Error),
    #[error("putting back what this peer had failed")]
    Restore(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    NoPing(#[from] probe::NoPing),
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Begins `run`: notes which of its probes answer, keeps `backup`, and starts
/// the process that puts it back unless the run is confirmed in time. Only one
/// run at a time: its directory is the lock.
pub fn begin(run: &Run, backup: Backup) -> Result<(), Error> {
    let answered = probe::answering(&run.probes)?;

    begin_in(
        Path::new(DIR),
        &run.id,
        run.confirm_within,
        backup,
        answered,
        spawn_watchdog,
    )
}

fn begin_in(
    dir: &Path,
    id: &str,
    confirm_within: u32,
    backup: Backup,
    answered: Vec<Probe>,
    watch: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), Error> {
    if let Some(parent) = dir.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let other = info(dir).map_or_else(|_| "unreadable".to_owned(), |info| info.id);
            return Err(Error::Busy { other });
        }
        Err(err) => return Err(err.into()),
    }

    let info = Info {
        id: id.to_owned(),
        deadline: now() + u64::from(confirm_within),
        backup,
        answered,
    };
    let armed = write_private(&dir.join(INFO), &serde_json::to_string(&info)?)
        .and_then(|()| write_private(&dir.join(ARMED), ""))
        .and_then(|()| watch(dir));
    if let Err(err) = armed {
        let _ = fs::remove_dir_all(dir);
        return Err(err.into());
    }

    Ok(())
}

/// A file only its owner can read.
fn write_private(path: &Path, text: &str) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| io::Write::write_all(&mut file, text.as_bytes()))
}

fn info(dir: &Path) -> Result<Info, Error> {
    Ok(serde_json::from_str(&fs::read_to_string(dir.join(INFO))?)?)
}

/// Starts this program again, apart from the session, to keep the deadline of
/// the run in `dir`. A running program keeps its file: the session's agent may
/// go, the watchdog stays.
fn spawn_watchdog(dir: &Path) -> io::Result<()> {
    Command::new(env::current_exe()?)
        .env(WATCHDOG, dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(drop)
}

/// The run `id` in `dir`, refused when there's another or none.
fn this_run(dir: &Path, id: &str) -> Result<Info, Error> {
    let info = match info(dir) {
        Ok(info) => info,
        Err(Error::Io(err)) if err.kind() == ErrorKind::NotFound => return Err(gone(dir, id)),
        Err(err) => return Err(err),
    };

    if info.id == id {
        Ok(info)
    } else {
        Err(Error::NoSuchRun { id: id.to_owned() })
    }
}

/// Where how the last run ended is kept: beside the run in `dir`.
fn last(dir: &Path) -> PathBuf {
    dir.with_file_name("last")
}

/// Why a run that isn't in `dir` can't be confirmed: it was rolled back, if
/// the last run was this one.
fn gone(dir: &Path, id: &str) -> Error {
    match fs::read_to_string(last(dir)) {
        Ok(last) if last.starts_with(&format!("{id} rolled back")) => {
            Error::TooLate { id: id.to_owned() }
        }
        _ => Error::NoSuchRun { id: id.to_owned() },
    }
}

/// Decides the run's outcome, `to`, unless it's decided already: whether this
/// call decided it.
fn decide(dir: &Path, to: &str) -> Result<bool, Error> {
    match fs::rename(dir.join(ARMED), dir.join(to)) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Ends the run in `dir`, saying how for whoever asks after it.
fn end(dir: &Path, id: &str, outcome: &str) {
    let _ = fs::write(last(dir), format!("{id} {outcome} at {}\n", now()));
    let _ = fs::remove_dir_all(dir);
}

/// The longest a check takes: what a tunnel may need to come back after a
/// reload, and then some.
const CHECK_FOR: u64 = 30;

/// Of the peers that answered when run `id` began, those that still do, and
/// those that don't, by name: each gets until the check's time (and the run's)
/// is up.
pub fn check(id: &str) -> Result<(Vec<String>, Vec<String>), Error> {
    let dir = Path::new(DIR);
    let info = this_run(dir, id)?;
    if !dir.join(ARMED).exists() {
        return Err(Error::TooLate { id: id.to_owned() });
    }

    // Some time left for the confirm after it.
    let left = info.deadline.saturating_sub(now() + 2);
    let within = Duration::from_secs(left.min(CHECK_FOR));

    Ok(probe::check(&info.answered, within)?)
}

/// Keeps what run `id` applied.
pub fn confirm(id: &str) -> Result<(), Error> {
    confirm_in(Path::new(DIR), id)
}

fn confirm_in(dir: &Path, id: &str) -> Result<(), Error> {
    this_run(dir, id)?;
    if !decide(dir, CONFIRMED)? {
        return Err(Error::TooLate { id: id.to_owned() });
    }
    end(dir, id, "confirmed");

    Ok(())
}

/// Puts back what the node had before run `id`, now.
pub fn rollback(id: &str) -> Result<(), Error> {
    rollback_in(Path::new(DIR), id, Backup::restore)
}

fn rollback_in(
    dir: &Path,
    id: &str,
    restore: impl FnOnce(&Backup) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
) -> Result<(), Error> {
    let info = this_run(dir, id)?;
    if !decide(dir, ROLLING_BACK)? {
        return Err(Error::TooLate { id: id.to_owned() });
    }
    let restored = restore(&info.backup);
    end(dir, id, "rolled back");

    restored.map_err(Error::Restore)
}

/// What the watchdog does at a tick: wait, or the run is over (decided by
/// someone else, or rolled back here at its deadline).
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    Wait,
    Over,
}

fn tick(
    dir: &Path,
    now: u64,
    restore: impl FnOnce(&Backup) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
) -> Tick {
    let Ok(info) = info(dir) else {
        return Tick::Over;
    };
    if !dir.join(ARMED).exists() {
        return Tick::Over;
    }
    if now < info.deadline {
        return Tick::Wait;
    }

    // Nobody confirmed in time: put back what the node had.
    let _ = rollback_in(dir, &info.id, restore);
    Tick::Over
}

/// The watchdog: when this process was started to keep a run's deadline
/// (`WATCHDOG`), keeps it, and ends the process. Called first thing by every
/// program that may run as the agent.
pub fn watch_if_asked() {
    let Some(dir) = env::var_os(WATCHDOG) else {
        return;
    };
    let dir = PathBuf::from(dir);

    while tick(&dir, now(), Backup::restore) == Tick::Wait {
        thread::sleep(Duration::from_secs(1));
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::test_support::{TempDir, mode};

    fn answered() -> Vec<Probe> {
        vec![Probe {
            peer: "Cabin".to_owned(),
            address: "10.100.0.2".parse().unwrap(),
        }]
    }

    fn backup() -> Backup {
        Backup::Linux {
            file: Some("[Interface]\n".to_owned()),
            active: true,
            enabled: true,
        }
    }

    /// A run dir in `temp`, begun as `id`, no watchdog started.
    fn begun(temp: &TempDir, id: &str, within: u32) -> PathBuf {
        let dir = temp.0.join("splot/run");
        begin_in(&dir, id, within, backup(), answered(), |_| Ok(())).unwrap();
        dir
    }

    #[test]
    fn a_run_keeps_what_the_node_had_readable_by_root_only() {
        let temp = TempDir::new("run-begin");
        let dir = begun(&temp, "r1", 120);

        assert_eq!(mode(dir.parent().unwrap()), 0o700);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(INFO)), 0o600);
        assert!(dir.join(ARMED).exists());
        let info = info(&dir).unwrap();
        assert_eq!(info.id, "r1");
        assert_eq!(info.backup, backup());
        assert_eq!(info.answered, answered());
        assert!(info.deadline >= now() + 119 && info.deadline <= now() + 120);
    }

    #[test]
    fn one_run_at_a_time() {
        let temp = TempDir::new("run-busy");
        let dir = begun(&temp, "r1", 120);

        let err = begin_in(&dir, "r2", 120, backup(), answered(), |_| Ok(())).unwrap_err();
        assert!(
            matches!(&err, Error::Busy { other } if other == "r1"),
            "{err}"
        );
        // The run that was there is untouched.
        assert_eq!(info(&dir).unwrap().id, "r1");
    }

    #[test]
    fn a_run_whose_watchdog_doesnt_start_doesnt_begin() {
        let temp = TempDir::new("run-no-watchdog");
        let dir = temp.0.join("splot/run");

        let err = begin_in(&dir, "r1", 120, backup(), answered(), |_| {
            Err(io::Error::other("no fork"))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        assert!(!dir.exists());
    }

    #[test]
    fn a_confirmed_run_ends_and_keeps_what_it_applied() {
        let temp = TempDir::new("run-confirm");
        let dir = begun(&temp, "r1", 120);

        let err = confirm_in(&dir, "r2").unwrap_err();
        assert!(matches!(err, Error::NoSuchRun { .. }), "{err}");
        assert!(dir.exists());

        confirm_in(&dir, "r1").unwrap();
        assert!(!dir.exists());
        // Its deadline passing does nothing now.
        assert_eq!(tick(&dir, u64::MAX, |_| panic!("restored")), Tick::Over);
    }

    #[test]
    fn a_rolled_back_run_puts_back_what_the_node_had_and_cant_be_confirmed() {
        let temp = TempDir::new("run-rollback");
        let dir = begun(&temp, "r1", 120);
        let restored = Cell::new(None);

        rollback_in(&dir, "r1", |backup| {
            restored.set(Some(backup.clone()));
            Ok(())
        })
        .unwrap();
        assert_eq!(restored.take(), Some(backup()));
        assert!(!dir.exists());
        // The last run, rolled back: too late to confirm it; another one the
        // node never had.
        let err = confirm_in(&dir, "r1").unwrap_err();
        assert!(matches!(err, Error::TooLate { .. }), "{err}");
        let err = confirm_in(&dir, "r0").unwrap_err();
        assert!(matches!(err, Error::NoSuchRun { .. }), "{err}");
    }

    #[test]
    fn the_outcome_is_decided_once() {
        // The watchdog rolled back first: the confirm is too late.
        let temp = TempDir::new("run-race");
        let dir = begun(&temp, "r1", 120);
        assert!(decide(&dir, ROLLING_BACK).unwrap());
        let err = confirm_in(&dir, "r1").unwrap_err();
        assert!(matches!(err, Error::TooLate { .. }), "{err}");

        // Confirmed first: the rollback is too late, and restores nothing.
        let temp = TempDir::new("run-race-2");
        let dir = begun(&temp, "r1", 120);
        assert!(decide(&dir, CONFIRMED).unwrap());
        let err = rollback_in(&dir, "r1", |_| panic!("restored")).unwrap_err();
        assert!(matches!(err, Error::TooLate { .. }), "{err}");
    }

    #[test]
    fn the_watchdog_waits_for_the_deadline_then_puts_back_what_the_node_had() {
        let temp = TempDir::new("run-watchdog");
        let dir = begun(&temp, "r1", 60);
        let deadline = info(&dir).unwrap().deadline;
        let restored = Cell::new(false);

        assert_eq!(
            tick(&dir, deadline - 1, |_| panic!("too early")),
            Tick::Wait
        );
        assert_eq!(
            tick(&dir, deadline, |_| {
                restored.set(true);
                Ok(())
            }),
            Tick::Over
        );
        assert!(restored.get());
        assert!(!dir.exists());
    }

    #[test]
    fn a_watchdog_whose_run_is_decided_ends_without_waiting() {
        // Confirmed, its directory not yet removed: the watchdog ends now, and
        // never restores.
        let temp = TempDir::new("run-decided");
        let dir = begun(&temp, "r1", 60);
        let deadline = info(&dir).unwrap().deadline;
        assert!(decide(&dir, CONFIRMED).unwrap());

        assert_eq!(tick(&dir, deadline - 1, |_| panic!("restored")), Tick::Over);
        assert_eq!(tick(&dir, deadline, |_| panic!("restored")), Tick::Over);
    }

    #[test]
    fn a_failed_restore_still_ends_the_run_and_says_so() {
        let temp = TempDir::new("run-restore-fails");
        let dir = begun(&temp, "r1", 120);

        let err = rollback_in(&dir, "r1", |_| Err("ubus isn't running".into())).unwrap_err();
        assert_eq!(err.to_string(), "putting back what this peer had failed");
        assert!(!dir.exists());
    }
}
