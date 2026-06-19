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

#[cfg(test)]
mod tests {
    use super::*;

    fn render(cmd: &UciBatchCommand) -> String {
        cmd.to_string()
    }

    fn builder() -> UciSectionBuilder {
        UciSectionBuilder::new("firewall", "my_rule", "rule")
    }

    #[test]
    fn new_emits_set_section_first() {
        let cmds = builder().build();
        assert_eq!(cmds.len(), 1);
        // path is file.spl_<name>, value is the section type
        assert_eq!(render(&cmds[0]), "set firewall.spl_my_rule='rule'");
    }

    #[test]
    fn set_appends_property() {
        let cmds = builder().set("dest", "lan").build();
        assert_eq!(cmds.len(), 2);
        assert_eq!(render(&cmds[1]), "set firewall.spl_my_rule.dest='lan'");
    }

    #[test]
    fn set_if_some_emits_when_some() {
        let cmds = builder().set_if_some("name", Some("hello")).build();
        assert_eq!(cmds.len(), 2);
        assert_eq!(render(&cmds[1]), "set firewall.spl_my_rule.name='hello'");
    }

    #[test]
    fn set_if_some_skips_when_none() {
        let cmds = builder().set_if_some("name", None::<String>).build();
        // only the initial section set
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn extend_list_sorted_output() {
        // Pass values in reverse order; expect them sorted alphabetically in the output.
        let cmds = builder()
            .extend_list("src_ip", ["10.0.1.0/24", "10.0.0.0/24", "192.168.0.0/16"])
            .build();
        // 1 section set + 3 add_list
        assert_eq!(cmds.len(), 4);
        assert_eq!(
            render(&cmds[1]),
            "add_list firewall.spl_my_rule.src_ip='10.0.0.0/24'"
        );
        assert_eq!(
            render(&cmds[2]),
            "add_list firewall.spl_my_rule.src_ip='10.0.1.0/24'"
        );
        assert_eq!(
            render(&cmds[3]),
            "add_list firewall.spl_my_rule.src_ip='192.168.0.0/16'"
        );
    }

    #[test]
    fn extend_list_empty_emits_no_add_list() {
        // Empty sources → no src_ip line → publicly reachable (key semantic for wan.sources).
        let cmds = builder()
            .extend_list("src_ip", std::iter::empty::<String>())
            .build();
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn build_preserves_insertion_order() {
        let cmds = builder()
            .set("target", "ACCEPT")
            .set("src", "mesh")
            .extend_list("proto", ["tcp", "udp"])
            .build();
        // section set, target, src, then sorted proto add_lists
        assert_eq!(render(&cmds[0]), "set firewall.spl_my_rule='rule'");
        assert_eq!(render(&cmds[1]), "set firewall.spl_my_rule.target='ACCEPT'");
        assert_eq!(render(&cmds[2]), "set firewall.spl_my_rule.src='mesh'");
        // "tcp" < "udp" — sorted
        assert_eq!(
            render(&cmds[3]),
            "add_list firewall.spl_my_rule.proto='tcp'"
        );
        assert_eq!(
            render(&cmds[4]),
            "add_list firewall.spl_my_rule.proto='udp'"
        );
    }
}
