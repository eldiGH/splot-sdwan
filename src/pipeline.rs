use std::io::{BufRead, BufReader};

use crate::{
    config::Config,
    consts,
    managers::UciManager,
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

    pub fn run(&self, config: &Config, own_name: &str) {
        let config_files_used: Vec<&'static str> = self.get_files_used().collect();

        let mut commands = generate_delete_commands(&config_files_used);

        for manager in &self.managers {
            commands.extend(manager.generate_commands(config, own_name));
        }

        for file in config_files_used {
            commands.push(UciBatchCommand::commit(file));
        }

        UciExecutor::batch(commands);
    }

    fn get_files_used(&self) -> impl Iterator<Item = &'static str> {
        self.managers.iter().map(|manager| manager.config_file())
    }
}

fn generate_delete_commands(files_used: &[&'static str]) -> Vec<UciBatchCommand> {
    let mut delete_commands: Vec<UciBatchCommand> = Vec::new();

    for file in files_used {
        let mut child = UciExecutor::show(file);
        let buf = BufReader::new(child.stdout.take().unwrap());

        let prefix = format!("{}.{}", file, consts::SPLOT_SECTION_PREFIX);

        for line in buf.lines() {
            let line = line.unwrap();

            if line.starts_with(&prefix) {
                let rest = &line[prefix.len()..];

                let Some(pos) = rest.find(|c| c == '=' || c == '.') else {
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

        child.wait().unwrap();
    }

    delete_commands
}
