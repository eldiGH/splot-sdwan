//! Applying the rendered config: stage it in one `uci batch`, commit it file by
//! file, then reload the services whose config changed.

use std::collections::HashSet;

use super::{
    Rendered, naming,
    reload::{self, Reload},
    uci::{self, UciBatchCommand},
};
use crate::consts;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Uci(#[from] uci::Error),
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
/// files have uncommitted changes, stages and commits splot's changes, then
/// reloads the services whose config changed. Returns the changed files.
pub(super) fn run(rendered: &Rendered) -> Result<Vec<&'static str>, Error> {
    let files = rendered.files();

    // uci keeps uncommitted changes in one place per file, shared by every uci
    // user on the router: committing or reverting ours would commit or revert
    // theirs too. So don't start while there are any.
    let mut pending = Vec::new();
    for file in &files {
        if uci::has_changes(file)? {
            pending.push(*file);
        }
    }
    if !pending.is_empty() {
        return Err(Error::PendingChanges(pending));
    }

    // Asked before anything is written.
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;

    let before = snapshot(&files)?;
    changeset(rendered, &before)?.apply()?;
    let after = snapshot(&files)?;
    let changed = changed_files(&before, &after);

    if let Some(reload) = Reload::new(&changed, naming::mesh_interface().to_string(), peer_update) {
        reload.run()?;
    }

    Ok(changed)
}

/// Prints what `run` would send to uci, and the reload after it.
pub(super) fn print(rendered: &Rendered) -> Result<(), Error> {
    let peer_update = reload::peer_update().map_err(Error::Netifd)?;

    let files = rendered.files();
    let current = snapshot(&files)?;

    for command in changeset(rendered, &current)?.commands() {
        println!("{}", command.redacted());
    }

    // As comments, so the output stays a valid `uci batch` script.
    if let Some(reload) = Reload::new(&files, naming::mesh_interface().to_string(), peer_update) {
        println!("# Then, if anything changed, splot reloads the services;");
        println!("# the network and WireGuard lines only if network changed:");
        for command in reload.commands() {
            println!("#   {command}");
        }
    }

    Ok(())
}

/// What replaces splot's sections in `current`: deletes for the old ones, then
/// the rendered ones.
fn changeset(rendered: &Rendered, current: &Snapshot) -> Result<Changeset, Error> {
    let generated: Vec<UciBatchCommand> = rendered.commands().cloned().collect();

    // Checked before anything touches uci.
    let duplicates = find_duplicate_sections(&generated);
    if !duplicates.is_empty() {
        return Err(Error::DuplicateSections(duplicates));
    }

    let mut changes = delete_commands(current);
    changes.extend(generated);

    Ok(Changeset {
        files: rendered.files(),
        changes,
    })
}

/// Everything `apply` sends to uci: the changes — replacing splot's sections — and
/// the files they touch. The changes are staged in a single `uci batch` without
/// commits; the files are committed only once uci accepted every line.
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

/// Section paths (`<file>.<section>`) that are created more than once.
///
/// uci silently merges two `set <file>.<section>='<type>'` of the same name into a
/// single section — options combined, list values accumulated — so two different
/// firewall rules would become one rule letting every source reach every
/// destination. Applying refuses such a batch instead.
pub(crate) fn find_duplicate_sections(commands: &[UciBatchCommand]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();

    for command in commands {
        // A section is created by `set <file>.<section>`: exactly one dot.
        // Options (`<file>.<section>.<option>`) have two.
        if let UciBatchCommand::Set(path, _) = command
            && path.matches('.').count() == 1
            && !seen.insert(path.as_str())
            && !duplicates.contains(path)
        {
            duplicates.push(path.clone());
        }
    }

    duplicates
}

/// Each file's `uci show` output, or `None` when uci doesn't know the file.
type Snapshot = Vec<(&'static str, Option<String>)>;

fn snapshot(files: &[&'static str]) -> Result<Snapshot, uci::Error> {
    files
        .iter()
        .map(|file| Ok((*file, uci::show(file)?)))
        .collect()
}

/// The files whose config differs between the two snapshots.
fn changed_files(before: &Snapshot, after: &Snapshot) -> Vec<&'static str> {
    before
        .iter()
        .zip(after)
        .filter(|((_, old), (_, new))| old != new)
        .map(|((file, _), _)| *file)
        .collect()
}

/// A delete for every splot-owned section (`<file>.spl_…`) in the snapshot.
fn delete_commands(snapshot: &Snapshot) -> Vec<UciBatchCommand> {
    let mut delete_commands: Vec<UciBatchCommand> = Vec::new();

    for (file, output) in snapshot {
        let Some(output) = output else {
            continue;
        };
        let prefix = format!("{}.{}", file, consts::SPLOT_SECTION_PREFIX);

        for line in output.lines() {
            if line.starts_with(&prefix) {
                let rest = &line[prefix.len()..];

                let Some(pos) = rest.find(['=', '.']) else {
                    continue;
                };

                if rest.as_bytes()[pos] == b'.' {
                    continue;
                }

                let full = &line[..prefix.len() + pos];
                let command = UciBatchCommand::del(full);

                delete_commands.push(command);
            }
        }
    }

    delete_commands
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn deletes_splot_sections_only() {
        let snapshot: Snapshot = vec![
            (
                "network",
                Some(
                    "network.loopback=interface
network.loopback.proto='static'
network.split_lan=interface
network.spl_mesh=interface
network.spl_mesh.proto='wireguard'
network.spl_wireguard_spl_mesh_Cabin=wireguard_spl_mesh"
                        .to_owned(),
                ),
            ),
            ("dhcp", None), // no such file yet
        ];
        let rendered: Vec<String> = delete_commands(&snapshot)
            .iter()
            .map(|c| c.to_string())
            .collect();
        assert_eq!(
            rendered,
            [
                "delete network.spl_mesh",
                "delete network.spl_wireguard_spl_mesh_Cabin",
            ]
        );
    }

    #[test]
    fn changed_files_are_those_whose_config_differs() {
        let before: Snapshot = vec![
            ("network", Some("network.spl_mesh=interface".to_owned())),
            ("firewall", Some("firewall.spl_zone_mesh=zone".to_owned())),
            ("dhcp", None),
        ];
        let after: Snapshot = vec![
            ("network", Some("network.spl_mesh=interface".to_owned())),
            ("firewall", Some("firewall.spl_zone_lan=zone".to_owned())),
            ("dhcp", Some("dhcp.spl_host_nas=host".to_owned())),
        ];
        assert_eq!(changed_files(&before, &after), ["firewall", "dhcp"]);
        assert!(changed_files(&before, &before).is_empty());
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

    #[test]
    fn generated_changes_contain_no_commit() {
        // The changes are staged in one `uci batch` and committed separately,
        // only once uci accepted every line. A commit among the changes would
        // write a file before that check.
        let example = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/splot.example.yml"));
        for node in ["Home", "Cabin"] {
            let rendered = rendered(example, node);
            let generated: Vec<&UciBatchCommand> = rendered.commands().collect();
            assert!(!generated.is_empty());
            assert!(
                !generated
                    .iter()
                    .any(|c| matches!(c, UciBatchCommand::Commit(_))),
                "{node}"
            );
        }
    }

    #[test]
    fn distinct_sections_pass() {
        let commands = [
            set("firewall.spl_rule_in_Home_ssh", "rule"),
            set("firewall.spl_rule_out_Home_ssh", "rule"),
            set("network.spl_rule_in_Home_ssh", "interface"), // same name, other file
        ];
        assert!(find_duplicate_sections(&commands).is_empty());
    }

    #[test]
    fn duplicate_section_is_reported_once() {
        let commands = [
            set("firewall.spl_x", "rule"),
            set("firewall.spl_x", "rule"),
            set("firewall.spl_x", "redirect"),
        ];
        assert_eq!(find_duplicate_sections(&commands), ["firewall.spl_x"]);
    }

    #[test]
    fn options_and_deletes_are_not_sections() {
        // The same option set twice, or a delete followed by a set, is no clash.
        let commands = [
            UciBatchCommand::del("firewall.spl_x"),
            set("firewall.spl_x", "rule"),
            set("firewall.spl_x.dest_port", "22"),
            set("firewall.spl_x.dest_port", "22"),
            UciBatchCommand::add_list("firewall.spl_x.proto", "tcp"),
        ];
        assert!(find_duplicate_sections(&commands).is_empty());
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
        let commands: Vec<UciBatchCommand> = rendered.commands().cloned().collect();
        assert_eq!(
            find_duplicate_sections(&commands),
            ["dhcp.spl_host_my_printer"]
        );
    }
}
