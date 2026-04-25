use std::{
    io::Write,
    process::{Child, Command, Stdio},
};

use crate::env;

#[derive(Debug)]
pub enum UciBatchCommand {
    Set(String, String),
    Del(String),
    Add(String, String),
    AddList(String, String),
    Commit(Option<String>),
}

impl UciBatchCommand {
    pub fn set(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::Set(path.into(), val.into())
    }

    pub fn del(path: impl Into<String>) -> Self {
        Self::Del(path.into())
    }

    pub fn add(config: impl Into<String>, section: impl Into<String>) -> Self {
        Self::Add(config.into(), section.into())
    }

    pub fn add_list(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::AddList(path.into(), val.into())
    }

    pub fn commit(config: impl Into<String>) -> Self {
        Self::Commit(Some(config.into()))
    }
}

impl std::fmt::Display for UciBatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(path, val) => write!(f, "set {path}='{val}'"),
            Self::Del(path) => write!(f, "delete {path}"),
            Self::Add(config, section) => write!(f, "add {config} {section}"),
            Self::AddList(path, val) => write!(f, "add_list {path}='{val}'"),

            Self::Commit(config) => {
                if let Some(config) = config {
                    write!(f, "commit {}", config)
                } else {
                    write!(f, "commit")
                }
            }
        }
    }
}

pub struct UciExecutor;

impl UciExecutor {
    fn base() -> Command {
        let mut command = Command::new("uci");

        if let Some(uci_config_dir) = env::uci_config_dir() {
            command.arg("-c").arg(uci_config_dir);
        }

        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());

        command
    }

    pub fn batch(commands: Vec<UciBatchCommand>) {
        let mut child = Self::base()
            .arg("batch")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let mut stdin = child.stdin.take().unwrap();

            for cmd in &commands {
                stdin.write_all(cmd.to_string().as_bytes()).unwrap();
                stdin.write_all(b"\n").unwrap();
            }
        }

        child.wait().unwrap();
    }

    pub fn show(file: &str) -> Child {
        Self::base()
            .arg("show")
            .arg(file)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }

    pub fn get(path: &str) -> Option<String> {
        let output = Self::base()
            .arg("get")
            .arg(path)
            .stdout(Stdio::piped())
            .output()
            .unwrap();

        if output.status.success() {
            let value = String::from_utf8(output.stdout).ok()?;
            Some(value.trim_end().to_owned())
        } else {
            None
        }
    }

    pub fn set(path: &str, value: &str) {
        Self::base()
            .arg("set")
            .arg(format!("{path}='{value}'"))
            .output()
            .unwrap();
    }
}
