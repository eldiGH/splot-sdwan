use crate::{
    config::Config,
    consts,
    managers::{NodeContext, UciManager},
    uci::{self, UciBatchCommand},
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

    pub fn register<M: UciManager + 'static>(mut self, manager: M) -> Self {
        self.managers.push(Box::new(manager));
        self
    }

    pub fn run(&self, config: &Config, node_context: &NodeContext) -> Result<(), uci::Error> {
        let commands = self.commands(config, node_context)?;
        uci::batch(&commands)?;
        Ok(())
    }

    pub fn print(&self, config: &Config, node_context: &NodeContext) -> Result<(), uci::Error> {
        let commands = self.commands(config, node_context)?;

        for command in commands {
            println!("{command}");
        }

        Ok(())
    }

    fn commands(
        &self,
        config: &Config,
        node_context: &NodeContext,
    ) -> Result<Vec<UciBatchCommand>, uci::Error> {
        let config_files_used: Vec<&'static str> = self.get_files_used().collect();

        let mut commands = generate_delete_commands(&config_files_used)?;

        for manager in &self.managers {
            commands.extend(manager.generate_commands(config, node_context));
        }

        for file in config_files_used {
            commands.push(UciBatchCommand::commit(file));
        }

        Ok(commands)
    }

    fn get_files_used(&self) -> impl Iterator<Item = &'static str> {
        self.managers.iter().map(|manager| manager.config_file())
    }
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
