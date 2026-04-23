use crate::{config::Config, uci::UciBatchCommand};

pub mod network;

#[derive(Debug)]
pub enum ManagerErrors {
    OwnNodeNotFound,
}

impl std::fmt::Display for ManagerErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerErrors::OwnNodeNotFound => {
                write!(f, "own node was not found in configuration")
            }
        }
    }
}

impl std::error::Error for ManagerErrors {}

pub trait UciManager {
    fn generate_commands(
        &self,
        config: &Config,
        own_name: &str,
    ) -> Result<Vec<UciBatchCommand>, ManagerErrors>;

    fn config_file(&self) -> &'static str;
    fn named_prefixes(&self) -> &'static [&'static str];
    fn anonymous_prefixes(&self) -> &'static [&'static str];
}
