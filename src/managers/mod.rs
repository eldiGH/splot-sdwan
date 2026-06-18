use std::fmt::Display;

use crate::{config::Config, consts, types::identifier::Identifier, uci::UciBatchCommand};

pub mod dhcp;
pub mod firewall;
pub mod network;

pub trait UciManager {
    fn generate_commands(&self, config: &Config, own_name: &Identifier) -> Vec<UciBatchCommand>;

    fn config_file(&self) -> &'static str;
}

struct UciSectionBuilder {
    path: String,
    commands: Vec<UciBatchCommand>,
}

impl UciSectionBuilder {
    fn new(file: &str, name: &str, section_type: &str) -> Self {
        let path = format!("{file}.{}{name}", consts::SPLOT_SECTION_PREFIX);

        let commands = vec![UciBatchCommand::set(&path, section_type)];

        Self { path, commands }
    }

    fn prop(&self, prop_name: &str) -> String {
        format!("{}.{prop_name}", self.path)
    }

    fn set(mut self, prop_name: &str, value: impl Into<String>) -> Self {
        self.commands
            .push(UciBatchCommand::set(self.prop(prop_name), value));

        self
    }

    fn set_if_some(self, prop_name: &str, value: Option<impl Into<String>>) -> Self {
        let Some(value) = value else { return self };

        self.set(prop_name, value)
    }

    fn extend_list(
        mut self,
        prop_name: &str,
        values: impl IntoIterator<Item = impl Display>,
    ) -> Self {
        let prop = self.prop(prop_name);

        let sorted_values = {
            let mut values = values
                .into_iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>();
            values.sort();

            values
                .into_iter()
                .map(|value| UciBatchCommand::add_list(prop.clone(), value))
        };

        self.commands.extend(sorted_values);

        self
    }

    fn build(self) -> Vec<UciBatchCommand> {
        self.commands
    }
}
