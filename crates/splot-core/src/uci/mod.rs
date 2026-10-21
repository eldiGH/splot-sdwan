//! uci's vocabulary: the commands splot sends it, the sections of its files,
//! the names splot gives them, and its files read as `uci export` prints them.

pub mod export;
pub mod naming;
pub mod section;

#[derive(Debug, Clone)]
pub enum UciBatchCommand {
    Set(String, String),
    Del(String),
    AddList(String, String),
    /// Moves a section to a position among all sections of its file.
    Reorder(String, usize),
    Commit(Option<String>),
}

impl UciBatchCommand {
    pub fn set(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::Set(path.into(), val.into())
    }

    pub fn del(path: impl Into<String>) -> Self {
        Self::Del(path.into())
    }

    pub fn add_list(path: impl Into<String>, val: impl Into<String>) -> Self {
        Self::AddList(path.into(), val.into())
    }

    pub fn reorder(path: impl Into<String>, position: usize) -> Self {
        Self::Reorder(path.into(), position)
    }

    pub fn commit(config: impl Into<String>) -> Self {
        Self::Commit(Some(config.into()))
    }
}

/// Maps an identifier to a valid uci section/option name. uci accepts only
/// `[A-Za-z0-9_]` there, while identifiers may also contain `-`, so `-` becomes `_`.
pub fn name(identifier: &str) -> String {
    identifier.replace('-', "_")
}

/// A value in single quotes, the way uci's parser reads it back. A `'` inside
/// ends the quote, so it goes in escaped: `it's` is `'it'\''s'`. Unescaped, the
/// rest of the value would be read as more of the command.
fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// A command splot won't send uci: its path has a character a uci name can't
/// have (paths aren't quoted), or its value a control character. Names the path
/// only: the value may be a key.
#[derive(Debug, thiserror::Error)]
#[error("refusing to send `{path}` to uci: {reason}")]
pub struct UnsafeCommand {
    pub path: String,
    pub reason: &'static str,
}

/// Why a command can't be sent to uci (see `UnsafeCommand`). Every value splot
/// sends comes from a checked type, so this guards against bugs.
pub fn check(command: &UciBatchCommand) -> Result<(), UnsafeCommand> {
    let (path, value) = match command {
        UciBatchCommand::Set(path, value) | UciBatchCommand::AddList(path, value) => {
            (path.as_str(), Some(value))
        }
        UciBatchCommand::Del(path) | UciBatchCommand::Reorder(path, _) => (path.as_str(), None),
        UciBatchCommand::Commit(file) => (file.as_deref().unwrap_or_default(), None),
    };
    let unsafe_command = |reason| {
        Err(UnsafeCommand {
            path: path.to_owned(),
            reason,
        })
    };

    // A file, section and option name, or an anonymous section (`@rule[2]`).
    let name_char = |c: char| c.is_ascii_alphanumeric() || "_.@[]-".contains(c);
    if !path.chars().all(name_char) {
        return unsafe_command("a character uci names can't have");
    }
    if value.is_some_and(|value| value.chars().any(char::is_control)) {
        return unsafe_command("a control character in the value");
    }

    Ok(())
}

impl std::fmt::Display for UciBatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(path, val) => write!(f, "set {path}={}", quoted(val)),
            Self::Del(path) => write!(f, "delete {path}"),
            Self::AddList(path, val) => write!(f, "add_list {path}={}", quoted(val)),
            Self::Reorder(path, position) => write!(f, "reorder {path}={position}"),

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

#[cfg(test)]
mod tests {
    use super::*;
    use section::Value;

    fn render(cmd: &UciBatchCommand) -> String {
        cmd.to_string()
    }

    #[test]
    fn set_command() {
        assert_eq!(
            render(&UciBatchCommand::set("firewall.spl_rule", "rule")),
            "set firewall.spl_rule='rule'"
        );
    }

    #[test]
    fn del_command() {
        assert_eq!(
            render(&UciBatchCommand::del("firewall.spl_old")),
            "delete firewall.spl_old"
        );
    }

    #[test]
    fn add_list_command() {
        assert_eq!(
            render(&UciBatchCommand::add_list(
                "firewall.spl_r.src_ip",
                "10.0.0.0/8"
            )),
            "add_list firewall.spl_r.src_ip='10.0.0.0/8'"
        );
    }

    #[test]
    fn commit_with_file() {
        assert_eq!(
            render(&UciBatchCommand::commit("firewall")),
            "commit firewall"
        );
    }

    #[test]
    fn commit_bare() {
        assert_eq!(render(&UciBatchCommand::Commit(None)), "commit");
    }

    #[test]
    fn a_quote_in_a_value_is_escaped_the_way_uci_reads_it() {
        assert_eq!(
            render(&UciBatchCommand::set("network.spl_x.name", "it's")),
            r"set network.spl_x.name='it'\''s'"
        );
        assert_eq!(
            render(&UciBatchCommand::add_list("network.spl_x.list", "a'b")),
            r"add_list network.spl_x.list='a'\''b'"
        );
    }

    #[test]
    fn a_quoted_value_reads_back_as_it_was() {
        // uci's file format quotes values the same way; the export parser reads
        // them the way uci does.
        for value in [
            "it's",
            "''",
            "a'b'c",
            r"back\slash",
            "spaces and ; set x.y=z",
        ] {
            let text = format!("package f\n\nconfig t 's'\n\toption o {}\n", quoted(value));
            let sections = export::parse(&text).unwrap();
            assert_eq!(
                sections[0].options,
                [("o".to_owned(), Value::Single(value.to_owned()))],
                "{value}"
            );
        }
    }

    #[test]
    fn a_control_character_or_a_path_uci_cant_name_is_refused() {
        let refused = |command: UciBatchCommand| match check(&command) {
            Err(UnsafeCommand { path, .. }) => path,
            Ok(()) => panic!("{command}: not refused"),
        };

        // The error names the path, never the value: it may be a key.
        assert_eq!(
            refused(UciBatchCommand::set("network.spl_x.key", "SECRET\nset x=1")),
            "network.spl_x.key"
        );
        assert_eq!(
            refused(UciBatchCommand::add_list("network.spl_x.l", "a\tb")),
            "network.spl_x.l"
        );
        assert_eq!(
            refused(UciBatchCommand::set("network.spl x.name", "v")),
            "network.spl x.name"
        );
        assert_eq!(
            refused(UciBatchCommand::del("network.spl_x;reboot")),
            "network.spl_x;reboot"
        );
        assert_eq!(
            refused(UciBatchCommand::reorder("network.spl_'x", 1)),
            "network.spl_'x"
        );
        let err = check(&UciBatchCommand::set("network.spl_x.key", "SECRET\n")).unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");

        // What splot sends.
        for command in [
            UciBatchCommand::set("network.spl_mesh.private_key", "ABC+/def="),
            UciBatchCommand::set(
                "network.spl_wireguard_spl_mesh_lte_cam",
                "wireguard_spl_mesh",
            ),
            UciBatchCommand::add_list("firewall.spl_rule_in_Home_ssh.src_ip", "10.0.0.0/8"),
            UciBatchCommand::set("firewall.spl_rule_in_Home_ssh.name", "[SPLOT] in: Home ssh"),
            UciBatchCommand::del("firewall.@rule[2]"),
            UciBatchCommand::reorder("network.spl_mesh", 7),
            UciBatchCommand::commit("network"),
        ] {
            assert!(check(&command).is_ok(), "{command}");
        }
    }

    #[test]
    fn value_with_spaces_is_quoted() {
        // The value is placed inside single-quotes; spaces inside are fine.
        let cmd = UciBatchCommand::set("network.spl_x.name", "hello world");
        assert_eq!(render(&cmd), "set network.spl_x.name='hello world'");
    }

    #[test]
    fn name_maps_hyphens_to_underscores() {
        // uci rejects '-' in section and option names ("uci: Invalid argument").
        assert_eq!(name("a-b-c"), "a_b_c");
        assert_eq!(name("plain_name"), "plain_name");
    }
}
