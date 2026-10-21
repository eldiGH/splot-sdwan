//! A uci section: its name, its type and its options.

use serde::{Deserialize, Serialize};

use super::UciBatchCommand;

/// An option's value: one value, or a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Single(String),
    List(Vec<String>),
}

/// A uci section: its name, its type and its options, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub section_type: String,
    pub options: Vec<(String, Value)>,
}

impl Section {
    /// The commands that create it in `file`: the section, then each option.
    pub fn commands(&self, file: &str) -> Vec<UciBatchCommand> {
        let path = format!("{file}.{}", self.name);
        let mut commands = vec![UciBatchCommand::set(&path, &self.section_type)];

        for (option, value) in &self.options {
            let option = format!("{path}.{option}");

            match value {
                Value::Single(value) => commands.push(UciBatchCommand::set(option, value)),
                Value::List(values) => commands.extend(
                    values
                        .iter()
                        .map(|value| UciBatchCommand::add_list(&option, value)),
                ),
            }
        }

        commands
    }
}
