//! Applying the rendered config: stage what differs from the current config in
//! one `uci batch`, commit the files that change, then reload their services.

use std::collections::HashSet;

use super::{
    Rendered, diff,
    export::{self, ParseError},
    naming, network,
    reload::{self, Reload},
    uci::{self, UciBatchCommand},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Uci(#[from] uci::Error),
    #[error("can't read the current uci config of {file}")]
    Export {
        file: &'static str,
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
    #[error(
        "{} already has uncommitted uci changes, which splot would commit or revert together with its own - review them with `uci changes <file>`, commit or revert them, then run splot again",
        .0.join(", ")
    )]
    PendingChanges(Vec<&'static str>),
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
        file: &'static str,
        committed: Vec<&'static str>,
        reverted: bool,
        #[source]
        cause: uci::Error,
    },
}

fn commit_failed_message(file: &str, committed: &[&str], reverted: bool) -> String {
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

/// Applies the rendered config and makes it live: refuses to start while its
/// files have uncommitted changes, stages what differs from the current config,
/// commits the files that change, then reloads their services. Returns those
/// files; none when the config already matches.
pub(super) fn run(rendered: &Rendered) -> Result<Vec<&'static str>, Error> {
    // uci keeps uncommitted changes in one place per file, shared by every uci
    // user on the router: committing or reverting ours would commit or revert
    // theirs too. So don't start while there are any.
    let mut pending = Vec::new();
    for file in rendered.files() {
        if uci::has_changes(file)? {
            pending.push(file);
        }
    }
    if !pending.is_empty() {
        return Err(Error::PendingChanges(pending));
    }

    // Asked before anything is written.
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;

    let changeset = changeset(rendered)?;
    if changeset.files.is_empty() {
        return Ok(Vec::new());
    }
    changeset.apply()?;

    if let Some(reload) = Reload::new(
        &changeset.files,
        naming::mesh_interface().to_string(),
        peer_update,
    ) {
        reload.run()?;
    }

    Ok(changeset.files)
}

/// Prints what `run` would send to uci, and the reload after it. `private_key` is
/// in the rendered config, so the diff is exact; it's printed as the placeholder.
pub(super) fn print(rendered: &Rendered, private_key: &str) -> Result<(), Error> {
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;
    let changeset = changeset(rendered)?;

    if changeset.files.is_empty() {
        println!("# Nothing to change.");
        return Ok(());
    }

    for command in changeset.commands() {
        match command {
            UciBatchCommand::Set(path, value) if value == private_key => {
                println!(
                    "{}",
                    UciBatchCommand::set(path, network::PRIVATE_KEY_PLACEHOLDER)
                );
            }
            command => println!("{command}"),
        }
    }

    // As comments, so the output stays a valid `uci batch` script.
    if let Some(reload) = Reload::new(
        &changeset.files,
        naming::mesh_interface().to_string(),
        peer_update,
    ) {
        println!("# Then splot reloads the services:");
        for command in reload.commands() {
            println!("#   {command}");
        }
    }

    Ok(())
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

    for (file, sections) in &rendered.files {
        let current = match uci::export(file)? {
            Some(text) => export::parse(&text).map_err(|cause| Error::Export { file, cause })?,
            None => Vec::new(),
        };
        // Spelled in uci here, while the sections the changes point at are alive.
        let file_changes = diff::commands(file, &current, &diff::diff(&current, sections));

        if !file_changes.is_empty() {
            files.push(*file);
            changes.extend(file_changes);
        }
    }

    Ok(Changeset { files, changes })
}

/// Everything `apply` sends to uci: the changes and the files they touch. The
/// changes are staged in a single `uci batch` without commits; the files are
/// committed only once uci accepted every line.
struct Changeset {
    files: Vec<&'static str>,
    changes: Vec<UciBatchCommand>,
}

impl Changeset {
    /// The changes followed by one commit per file, as `--dry-run` shows them.
    fn commands(&self) -> impl Iterator<Item = UciBatchCommand> {
        self.changes
            .iter()
            .cloned()
            .chain(self.files.iter().map(|file| UciBatchCommand::commit(*file)))
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
                    file,
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
fn revert(files: &[&'static str]) -> Result<(), uci::Error> {
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
fn find_duplicate_sections(rendered: &Rendered) -> Vec<String> {
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
    use crate::backend::openwrt::section::Section;
    use crate::{
        backend::{
            Backend,
            openwrt::{OpenWrtBackend, splot_config::SplotConfig},
        },
        plan,
        test_support::checked,
    };

    fn rendered(yaml: &str, node: &str) -> Rendered {
        let network = checked(yaml);
        let plan = plan::plan(&network, &node.parse().unwrap()).unwrap();

        OpenWrtBackend::new(SplotConfig::for_tests("FAKE_MESH_KEY")).render(&plan)
    }

    fn set(path: &str, value: &str) -> UciBatchCommand {
        UciBatchCommand::set(path, value)
    }

    #[test]
    fn changes_come_first_then_one_commit_per_file() {
        let changeset = Changeset {
            files: vec!["network", "dhcp"],
            changes: vec![
                UciBatchCommand::del("network.spl_old"),
                set("dhcp.spl_host_a", "host"),
            ],
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
            commit_failed_message("dhcp", &["network", "firewall"], false),
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
                    "firewall",
                    vec![
                        section("spl_rule_in_Home_ssh", "rule"),
                        section("spl_rule_out_Home_ssh", "rule"),
                    ],
                ),
                // Same name, other file.
                (
                    "network",
                    vec![section("spl_rule_in_Home_ssh", "interface")],
                ),
            ],
        };
        assert!(find_duplicate_sections(&rendered).is_empty());
    }

    #[test]
    fn duplicate_section_is_reported_once() {
        let rendered = Rendered {
            files: vec![(
                "firewall",
                vec![
                    section("spl_x", "rule"),
                    section("spl_x", "rule"),
                    section("spl_x", "redirect"),
                ],
            )],
        };
        assert_eq!(find_duplicate_sections(&rendered), ["firewall.spl_x"]);
    }

    #[test]
    fn hyphen_and_underscore_names_clash_in_real_output() {
        // `my-printer` and `my_printer` are distinct identifiers, but both map to
        // the uci section `spl_host_my_printer`. The guard must catch what the
        // generators produce, not just hand-built commands.
        let rendered = rendered(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          my-printer:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
          my_printer:
            ip: 192.168.1.21
            macs: AA:BB:CC:DD:EE:02
",
            "Home",
        );
        assert_eq!(
            find_duplicate_sections(&rendered),
            ["dhcp.spl_host_my_printer"]
        );
    }
}
