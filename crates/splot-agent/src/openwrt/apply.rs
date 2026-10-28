//! Applying the rendered config: stage what differs from the current config in
//! one `uci batch`, commit the files that change, then reload their services.

use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

use splot_core::protocol::{Changes, Run};

use splot_core::{
    protocol::openwrt::Rendered,
    uci::{
        export::{self, ParseError},
        naming,
        slot::Slot,
    },
};

use super::{
    diff,
    reload::{self, PeerUpdate, Reload},
    slot,
    uci::{self, UciBatchCommand},
};
use crate::{
    run::{self, Backup},
    wg,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Uci(#[from] uci::Error),
    #[error(transparent)]
    RunState(#[from] run::Error),
    #[error("can't read {} to keep it for the run", .0.display())]
    Backup(PathBuf, #[source] io::Error),
    #[error("can't put back {}", .0.display())]
    Restore(PathBuf, #[source] io::Error),
    #[error("can't drop the WireGuard session of a peer whose preshared key changed")]
    FreshSession(#[source] wg::Error),
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
    NotConfirmed(#[from] crate::node::NotConfirmed),
    #[error("can't read the current uci config of {file}")]
    Export {
        file: String,
        #[source]
        cause: ParseError,
    },
    #[error("failed to ask netifd how WireGuard picks up changed peers")]
    Netifd(#[source] reload::Error),
    #[error(transparent)]
    Reload(#[from] reload::Error),
    #[error(
        "generated config contains several sections named {}, which uci would silently merge into one - rename one of the objects behind each (names that differ only in '-' vs '_', or in where a '_' falls, end up identical)",
        .0.join(", ")
    )]
    DuplicateSections(Vec<String>),
    #[error(transparent)]
    MissingPsks(#[from] crate::secret::MissingPsks),
    #[error(
        "{} already has uncommitted uci changes, which splot would commit or revert together with its own - review them with `uci changes <file>`, commit or revert them, then run splot again",
        .0.join(", ")
    )]
    PendingChanges(Vec<String>),
    #[error(
        "uci rejected the generated changes; nothing was committed and splot's staged changes were reverted"
    )]
    Rejected(#[source] uci::Error),
    #[error(
        "uci rejected the generated changes; nothing was committed, but reverting splot's staged changes failed too ({revert}) - check `uci changes`"
    )]
    RevertFailed {
        #[source]
        cause: uci::Error,
        revert: uci::Error,
    },
    #[error("{}", commit_failed_message(file, committed, *reverted))]
    CommitFailed {
        file: String,
        committed: Vec<String>,
        reverted: bool,
        #[source]
        cause: uci::Error,
    },
}

fn commit_failed_message(file: &str, committed: &[String], reverted: bool) -> String {
    let outcome = if committed.is_empty() {
        "nothing was committed".to_owned()
    } else {
        format!(
            "{} already had the new config committed, {file} and the files after it keep the old one",
            committed.join(", ")
        )
    };
    let revert = if reverted {
        "their staged changes were reverted"
    } else {
        "reverting their staged changes failed too - check `uci changes`"
    };

    format!("committing {file} failed: {outcome} ({revert})")
}

/// What a run prepared: the changes its go applies.
pub struct Prepared {
    changeset: Changeset,
    peer_update: PeerUpdate,
    changes: Changes,
}

impl Prepared {
    /// What the go changes, as the dry run shows it.
    pub fn changes(&self) -> &Changes {
        &self.changes
    }
}

/// Begins `run` to apply the rendered config, changing nothing yet: refuses to
/// start while its files have uncommitted changes, works out what differs from
/// the current config, and keeps the files that change for the run.
pub(super) fn prepare(rendered: &Rendered, run: &Run) -> Result<Prepared, Error> {
    // uci keeps uncommitted changes in one place per file, shared by every uci
    // user on the router: committing or reverting ours would commit or revert
    // theirs too. So don't start while there are any.
    let mut pending = Vec::new();
    for file in rendered.files() {
        if uci::has_changes(file)? {
            pending.push(file.to_owned());
        }
    }
    if !pending.is_empty() {
        return Err(Error::PendingChanges(pending));
    }

    // Asked before anything is written.
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;

    let changeset = changeset(rendered)?;
    let backup = if changeset.files.is_empty() {
        None
    } else {
        let files = changeset
            .files
            .iter()
            .map(|file| {
                let path = uci::file_path(file);
                let text = read_optional(&path).map_err(|err| Error::Backup(path.clone(), err))?;
                Ok((path, text))
            })
            .collect::<Result<_, Error>>()?;
        Some(Backup::OpenWrt { files })
    };
    run::begin(run, backup)?;

    Ok(Prepared {
        changes: described(&changeset, peer_update, &rendered.secrets),
        changeset,
        peer_update,
    })
}

/// Applies what run `id` prepared and makes it live: stages the changes,
/// commits their files, then reloads their services. When any of that fails,
/// puts the files back. Returns the files that changed.
pub(super) fn go(prepared: &Prepared, id: &str) -> Result<Vec<String>, Error> {
    run::go(id)?;
    let Prepared {
        changeset,
        peer_update,
        changes,
    } = prepared;
    if changeset.files.is_empty() {
        return Ok(Vec::new());
    }

    let applied = changeset
        .apply()
        .and_then(|()| fresh_sessions(&changeset.fresh))
        .and_then(|()| {
            match Reload::new(
                &changeset.files,
                naming::mesh_interface().to_string(),
                *peer_update,
            ) {
                Some(reload) => reload.run().map_err(Error::from),
                None => Ok(()),
            }
        });
    if let Err(cause) = applied {
        let cause = Box::new(cause);
        return Err(match run::rollback(id) {
            Ok(()) => Error::PutBack(cause),
            Err(rollback) => Error::NotPutBack { cause, rollback },
        });
    }

    Ok(changes.summary.clone())
}

/// Drops the sessions of the peers whose public keys are `keys`, from splot's
/// live WireGuard interface (when it's up: one that isn't has none).
fn fresh_sessions(keys: &[String]) -> Result<(), Error> {
    let interface = naming::mesh_interface().to_string();
    if keys.is_empty() || !Path::new("/sys/class/net").join(&interface).exists() {
        return Ok(());
    }

    for key in keys {
        wg::remove_peer(&interface, key).map_err(Error::FreshSession)?;
    }

    Ok(())
}

/// What the file at `path` holds; none when there's no such file.
fn read_optional(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Puts back the uci files a run changed, each as it was (`files`: none for
/// one there wasn't), and makes them live: the services reload, and splot's
/// WireGuard interface comes up as it was, when it's still there.
pub(super) fn restore(files: &[(PathBuf, Option<String>)]) -> Result<(), Error> {
    for (path, text) in files {
        let restored = match text {
            Some(text) => fs::write(path, text),
            None => fs::remove_file(path).or_else(|err| match err.kind() {
                io::ErrorKind::NotFound => Ok(()),
                _ => Err(err),
            }),
        };
        restored.map_err(|err| Error::Restore(path.clone(), err))?;
    }

    let names: Vec<String> = files
        .iter()
        .filter_map(|(path, _)| Some(path.file_name()?.to_str()?.to_owned()))
        .collect();
    let mesh = naming::mesh_interface().to_string();
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;
    let mesh_is_there = uci::get(&format!("{}.{mesh}", reload::NETWORK))?.is_some();
    if let Some(reload) = Reload::new(&names, mesh, peer_update) {
        let reload = if mesh_is_there {
            reload
        } else {
            reload.without_interface()
        };
        reload.run()?;
    }

    Ok(())
}

/// What `go` would change: the files, and what it would send to uci and the
/// reload after it, as the dry run shows it.
pub(super) fn print(rendered: &Rendered) -> Result<Changes, Error> {
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;
    let changeset = changeset(rendered)?;

    Ok(described(&changeset, peer_update, &rendered.secrets))
}

/// What `changeset` changes, and the reload after it. The secrets are in it,
/// so the diff is exact; they're shown as their placeholders (`secrets`).
fn described(changeset: &Changeset, peer_update: PeerUpdate, secrets: &[Slot]) -> Changes {
    if changeset.files.is_empty() {
        return Changes::none();
    }

    let mut text = String::new();
    for command in changeset.commands() {
        text.push_str(&format!("{}\n", slot::masked(command, secrets)));
    }

    // As comments, so the output stays a valid `uci batch` script.
    if let Some(reload) = Reload::new(
        &changeset.files,
        naming::mesh_interface().to_string(),
        peer_update,
    ) {
        text.push_str("# Then splot reloads the services:\n");
        for command in reload.commands() {
            text.push_str(&format!("#   {command}\n"));
        }
    }

    Changes {
        summary: changeset.files.clone(),
        text,
    }
}

/// What turns the current config into the rendered one: for every file, the
/// changes to splot's sections (see `diff`), read against what `uci export` shows.
fn changeset(rendered: &Rendered) -> Result<Changeset, Error> {
    // Checked before anything touches uci.
    let duplicates = find_duplicate_sections(rendered);
    if !duplicates.is_empty() {
        return Err(Error::DuplicateSections(duplicates));
    }

    let mut files = Vec::new();
    let mut changes = Vec::new();
    let mut fresh = Vec::new();

    for (file, sections) in &rendered.files {
        let current = match uci::export(file)? {
            Some(text) => export::parse(&text).map_err(|cause| Error::Export {
                file: file.clone(),
                cause,
            })?,
            None => Vec::new(),
        };
        let diff = diff::diff(&current, sections);
        fresh.extend(diff::psk_changed(&diff));
        // Spelled in uci here, while the sections the changes point at are alive.
        let file_changes = diff::commands(file, &current, &diff);

        if !file_changes.is_empty() {
            files.push(file.clone());
            changes.extend(file_changes);
        }
    }

    Ok(Changeset {
        files,
        changes,
        fresh,
    })
}

/// Everything `apply` sends to uci: the changes and the files they touch. The
/// changes are staged in a single `uci batch` without commits; the files are
/// committed only once uci accepted every line.
struct Changeset {
    files: Vec<String>,
    changes: Vec<UciBatchCommand>,
    /// The peers whose preshared key changes: their sessions go before the
    /// reload, which brings them back with the new key.
    fresh: Vec<String>,
}

impl Changeset {
    /// The changes followed by one commit per file, as `--dry-run` shows them.
    fn commands(&self) -> impl Iterator<Item = UciBatchCommand> {
        self.changes
            .iter()
            .cloned()
            .chain(self.files.iter().map(UciBatchCommand::commit))
    }

    fn apply(&self) -> Result<(), Error> {
        if let Err(cause) = uci::batch(&self.changes) {
            return Err(match revert(&self.files) {
                Ok(()) => Error::Rejected(cause),
                Err(revert) => Error::RevertFailed { cause, revert },
            });
        }

        // uci writes each file separately, so committing several isn't atomic: a
        // failure (e.g. a full flash) can leave earlier files committed.
        for (index, file) in self.files.iter().enumerate() {
            if let Err(cause) = uci::commit(file) {
                let reverted = revert(&self.files[index..]).is_ok();

                return Err(Error::CommitFailed {
                    file: file.clone(),
                    committed: self.files[..index].to_vec(),
                    reverted,
                    cause,
                });
            }
        }

        Ok(())
    }
}

/// Reverts every file, even after one of them failed, and reports the first failure.
fn revert(files: &[String]) -> Result<(), uci::Error> {
    let mut first_failure = None;

    for file in files {
        if let Err(err) = uci::revert(file) {
            first_failure.get_or_insert(err);
        }
    }

    first_failure.map_or(Ok(()), Err)
}

/// Sections (`<file>.<section>`) rendered more than once in one file.
///
/// uci silently merges two sections of the same name into one — options
/// combined, list values accumulated — so two different firewall rules would
/// become one rule letting every source reach every destination. Applying
/// refuses such a config instead.
pub fn find_duplicate_sections(rendered: &Rendered) -> Vec<String> {
    let mut duplicates = Vec::new();

    for (file, sections) in &rendered.files {
        let mut seen = HashSet::new();

        for section in sections {
            let path = format!("{file}.{}", section.name);

            if !seen.insert(section.name.as_str()) && !duplicates.contains(&path) {
                duplicates.push(path);
            }
        }
    }

    duplicates
}

#[cfg(test)]
mod tests {
    use super::*;
    use splot_core::uci::section::Section;

    fn set(path: &str, value: &str) -> UciBatchCommand {
        UciBatchCommand::set(path, value)
    }

    #[test]
    fn changes_come_first_then_one_commit_per_file() {
        let changeset = Changeset {
            files: vec!["network".to_owned(), "dhcp".to_owned()],
            changes: vec![
                UciBatchCommand::del("network.spl_old"),
                set("dhcp.spl_host_a", "host"),
            ],
            fresh: Vec::new(),
        };
        let rendered: Vec<String> = changeset.commands().map(|c| c.to_string()).collect();
        assert_eq!(
            rendered,
            [
                "delete network.spl_old",
                "set dhcp.spl_host_a='host'",
                "commit network",
                "commit dhcp",
            ]
        );
    }

    #[test]
    fn commit_failure_says_which_files_have_the_new_config() {
        assert_eq!(
            commit_failed_message("network", &[], true),
            "committing network failed: nothing was committed (their staged changes were reverted)"
        );
        assert_eq!(
            commit_failed_message(
                "dhcp",
                &["network".to_owned(), "firewall".to_owned()],
                false
            ),
            "committing dhcp failed: network, firewall already had the new config committed, dhcp and the files after it keep the old one (reverting their staged changes failed too - check `uci changes`)"
        );
    }

    /// A section with no options.
    fn section(name: &str, section_type: &str) -> Section {
        Section {
            name: name.to_owned(),
            section_type: section_type.to_owned(),
            options: Vec::new(),
        }
    }

    #[test]
    fn distinct_sections_pass() {
        let rendered = Rendered {
            files: vec![
                (
                    "firewall".to_owned(),
                    vec![
                        section("spl_rule_in_Home_ssh", "rule"),
                        section("spl_rule_out_Home_ssh", "rule"),
                    ],
                ),
                // Same name, other file.
                (
                    "network".to_owned(),
                    vec![section("spl_rule_in_Home_ssh", "interface")],
                ),
            ],
            secrets: Vec::new(),
            ..super::super::empty()
        };
        assert!(find_duplicate_sections(&rendered).is_empty());
    }

    #[test]
    fn duplicate_section_is_reported_once() {
        let rendered = Rendered {
            files: vec![(
                "firewall".to_owned(),
                vec![
                    section("spl_x", "rule"),
                    section("spl_x", "rule"),
                    section("spl_x", "redirect"),
                ],
            )],
            secrets: Vec::new(),
            ..super::super::empty()
        };
        assert_eq!(find_duplicate_sections(&rendered), ["firewall.spl_x"]);
    }
}
