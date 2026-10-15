use std::collections::HashSet;

use crate::{
    config::Config,
    consts,
    managers::{NodeContext, UciManager},
    uci::{self, UciBatchCommand},
};

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error(transparent)]
    Uci(#[from] uci::Error),
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

pub struct UciPipeline {
    managers: Vec<Box<dyn UciManager>>,
}

impl Default for UciPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl UciPipeline {
    pub fn new() -> Self {
        Self { managers: vec![] }
    }

    pub fn register<M: UciManager + 'static>(mut self, manager: M) -> Self {
        self.managers.push(Box::new(manager));
        self
    }

    pub fn run(&self, config: &Config, node_context: &NodeContext) -> Result<(), PipelineError> {
        // uci keeps uncommitted changes in one place per file, shared by every uci
        // user on the router: committing or reverting ours would commit or revert
        // theirs too. So don't start while there are any.
        let mut pending = Vec::new();
        for file in self.get_files_used() {
            if uci::has_changes(file)? {
                pending.push(file);
            }
        }
        if !pending.is_empty() {
            return Err(PipelineError::PendingChanges(pending));
        }

        self.changeset(config, node_context)?.apply()
    }

    pub fn print(&self, config: &Config, node_context: &NodeContext) -> Result<(), PipelineError> {
        for command in self.changeset(config, node_context)?.commands() {
            println!("{}", command.redacted());
        }

        Ok(())
    }

    fn generate(&self, config: &Config, node_context: &NodeContext) -> Vec<UciBatchCommand> {
        self.managers
            .iter()
            .flat_map(|manager| manager.generate_commands(config, node_context))
            .collect()
    }

    fn changeset(
        &self,
        config: &Config,
        node_context: &NodeContext,
    ) -> Result<Changeset, PipelineError> {
        let files: Vec<&'static str> = self.get_files_used().collect();
        let generated = self.generate(config, node_context);

        // Checked before anything touches uci.
        let duplicates = find_duplicate_sections(&generated);
        if !duplicates.is_empty() {
            return Err(PipelineError::DuplicateSections(duplicates));
        }

        let mut changes = generate_delete_commands(&files)?;
        changes.extend(generated);

        Ok(Changeset { files, changes })
    }

    fn get_files_used(&self) -> impl Iterator<Item = &'static str> {
        self.managers.iter().map(|manager| manager.config_file())
    }
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

    fn apply(&self) -> Result<(), PipelineError> {
        if let Err(cause) = uci::batch(&self.changes) {
            return Err(match revert(&self.files) {
                Ok(()) => PipelineError::Rejected(cause),
                Err(revert) => PipelineError::RevertFailed { cause, revert },
            });
        }

        // uci writes each file separately, so committing several isn't atomic: a
        // failure (e.g. a full flash) can leave earlier files committed.
        for (index, file) in self.files.iter().enumerate() {
            if let Err(cause) = uci::commit(file) {
                let reverted = revert(&self.files[index..]).is_ok();

                return Err(PipelineError::CommitFailed {
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
/// destination. The pipeline refuses such a batch instead.
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

fn generate_delete_commands(
    files_used: &[&'static str],
) -> Result<Vec<UciBatchCommand>, uci::Error> {
    let mut delete_commands: Vec<UciBatchCommand> = Vec::new();

    for file in files_used {
        let Some(output) = uci::show(file)? else {
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

    Ok(delete_commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        managers::{dhcp::DhcpManager, firewall::FirewallManager, network::NetworkManager},
        splot_config::SplotConfig,
        test_support::config,
        types::identifier::Identifier,
    };

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

    #[test]
    fn generated_changes_contain_no_commit() {
        // The changes are staged in one `uci batch` and committed separately,
        // only once uci accepted every line. A commit among the changes would
        // write a file before that check.
        let cfg = config(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        let pipeline = UciPipeline::new()
            .register(NetworkManager)
            .register(FirewallManager)
            .register(DhcpManager);
        for (node_name, node) in &cfg.nodes {
            let vpn_keys: Vec<(&str, &str)> = node
                .vpn_interfaces
                .keys()
                .map(|name| (name.as_ref(), "FAKE_VPN_KEY"))
                .collect();
            let splot_config = SplotConfig::for_tests("FAKE_MESH_KEY", &vpn_keys);
            let generated = pipeline.generate(
                &cfg,
                &NodeContext {
                    own_name: node_name,
                    own_node: node,
                    splot_config: &splot_config,
                },
            );
            assert!(!generated.is_empty());
            assert!(
                !generated
                    .iter()
                    .any(|c| matches!(c, UciBatchCommand::Commit(_))),
                "{node_name}"
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
        let cfg = config(
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
        );
        let own_name: Identifier = "Home".parse().unwrap();
        let splot_config = SplotConfig::for_tests("FAKE_MESH_KEY", &[]);
        let commands = DhcpManager.generate_commands(
            &cfg,
            &NodeContext {
                own_name: &own_name,
                own_node: &cfg.nodes[&own_name],
                splot_config: &splot_config,
            },
        );
        assert_eq!(
            find_duplicate_sections(&commands),
            ["dhcp.spl_host_my_printer"]
        );
    }
}
