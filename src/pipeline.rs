use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
};

use crate::{
    config::Config,
    managers::{ManagerErrors, UciManager},
    uci::{UciBatchCommand, UciExecutor},
};

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

    pub fn add(mut self, manager: Box<dyn UciManager>) -> Self {
        self.managers.push(manager);
        self
    }

    pub fn run(&self, config: &Config) -> Result<(), ManagerErrors> {
        let prefixes_to_delete = self.generate_delete_config_prefixes();

        let mut commands = generate_delete_commands(&prefixes_to_delete);

        for manager in &self.managers {
            commands.extend(manager.generate_commands(config, "Jawo")?);
        }

        for file in prefixes_to_delete.into_keys() {
            commands.push(UciBatchCommand::commit(file));
        }

        UciExecutor::batch(commands);

        Ok(())
    }

    fn generate_delete_config_prefixes(&self) -> HashMap<String, Vec<(bool, String)>> {
        let mut config_prefixes: HashMap<String, Vec<(bool, String)>> = HashMap::new();

        for manager in &self.managers {
            let config_file = manager.config_file();
            let named_prefixes = manager.named_prefixes();
            let anonymous_prefixes = manager.anonymous_prefixes();

            let prefixes = config_prefixes.entry(config_file.to_owned()).or_default();

            for named_prefix in named_prefixes {
                prefixes.push((false, format!("{config_file}.{named_prefix}")));
            }

            for anonymous_prefix in anonymous_prefixes {
                prefixes.push((true, format!("{config_file}.@{anonymous_prefix}")));
            }
        }

        config_prefixes
    }
}

fn generate_delete_commands(
    prefixes_to_delete: &HashMap<String, Vec<(bool, String)>>,
) -> Vec<UciBatchCommand> {
    let mut delete_commands: Vec<UciBatchCommand> = Vec::new();

    for (file, prefixes) in prefixes_to_delete {
        let mut child = UciExecutor::show(file);

        let buf = BufReader::new(child.stdout.take().unwrap());

        'line_loop: for line in buf.lines() {
            let line = line.unwrap();

            for (is_anonymous, prefix) in prefixes {
                if line.starts_with(prefix) {
                    let rest = &line[prefix.len()..];
                    match rest.find(|c| c == '=' || c == '.') {
                        Some(pos) if rest.as_bytes()[pos] == b'=' => {
                            let full = &line[..prefix.len() + pos];
                            let command = if *is_anonymous {
                                let base = full.rfind('[').map_or(full, |p| &full[..p]);
                                UciBatchCommand::del(format!("{}[0]", base))
                            } else {
                                UciBatchCommand::del(full)
                            };
                            delete_commands.push(command);
                            continue 'line_loop;
                        }
                        _ => break,
                    }
                }
            }
        }

        child.wait().unwrap();
    }

    delete_commands
}
