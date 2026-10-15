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
        let commands = self.commands(config, node_context)?;
        uci::batch(&commands)?;
        Ok(())
    }

    pub fn print(&self, config: &Config, node_context: &NodeContext) -> Result<(), PipelineError> {
        let commands = self.commands(config, node_context)?;

        for command in commands {
            println!("{}", command.redacted());
        }

        Ok(())
    }

    fn commands(
        &self,
        config: &Config,
        node_context: &NodeContext,
    ) -> Result<Vec<UciBatchCommand>, PipelineError> {
        let config_files_used: Vec<&'static str> = self.get_files_used().collect();

        let mut generated = Vec::new();
        for manager in &self.managers {
            generated.extend(manager.generate_commands(config, node_context));
        }

        // Checked before anything touches uci.
        let duplicates = find_duplicate_sections(&generated);
        if !duplicates.is_empty() {
            return Err(PipelineError::DuplicateSections(duplicates));
        }

        let mut commands = generate_delete_commands(&config_files_used)?;
        commands.extend(generated);

        for file in config_files_used {
            commands.push(UciBatchCommand::commit(file));
        }

        Ok(commands)
    }

    fn get_files_used(&self) -> impl Iterator<Item = &'static str> {
        self.managers.iter().map(|manager| manager.config_file())
    }
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
        managers::dhcp::DhcpManager, splot_config::SplotConfig, test_support::config,
        types::identifier::Identifier,
    };

    fn set(path: &str, value: &str) -> UciBatchCommand {
        UciBatchCommand::set(path, value)
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
