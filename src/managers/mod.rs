use std::{fmt::Display, iter};

use crate::{
    config::{Config, Node},
    model::Network,
    splot_config::SplotConfig,
    types::identifier::Identifier,
    uci::UciBatchCommand,
};

pub mod dhcp;
pub mod firewall;
pub mod naming;
pub mod network;

use naming::UciSectionName;

pub trait UciManager {
    /// What `config` describes, as uci commands for one node. The generators read
    /// what the checked model holds from `network`, and the rest, for now, from
    /// `config`.
    fn generate_commands(
        &self,
        config: &Config,
        network: &Network,
        node_context: &NodeContext,
    ) -> Vec<UciBatchCommand>;

    fn config_file(&self) -> &'static str;
}

pub struct NodeContext<'a> {
    pub own_name: &'a Identifier,
    pub own_node: &'a Node,
    pub splot_config: &'a SplotConfig,
}

/// A generated struct as one uci section. Its section name follows from what it
/// is: `spl_<section type>_<id>`.
trait UciSection {
    /// The uci file the section lives in.
    const FILE: &'static str;

    /// The uci section type (`rule`, `redirect`, `host`, …). It also leads the
    /// section name: uci has one namespace per file, and the type keeps sections
    /// of different types apart.
    fn section_type(&self) -> &str;

    /// What tells this section apart from other sections of the same type.
    fn id(&self) -> impl IntoIterator<Item = &str>;

    /// Everything after the line that creates the section.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder;

    fn section_name(&self) -> UciSectionName {
        UciSectionName::new(iter::once(self.section_type()).chain(self.id()))
    }

    fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        let section = UciSectionBuilder::new(Self::FILE, &self.section_name(), self.section_type());

        self.options(section).build()
    }
}

struct UciSectionBuilder {
    path: String,
    commands: Vec<UciBatchCommand>,
}

impl UciSectionBuilder {
    fn new(file: &str, name: &UciSectionName, section_type: &str) -> Self {
        let path = format!("{file}.{name}");

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
    use std::fmt::Write;

    use super::*;
    use crate::test_support;

    fn render(cmd: &UciBatchCommand) -> String {
        cmd.to_string()
    }

    // ── Snapshot of everything generated for the example config ────────────
    //
    // Pins the complete UCI output of all managers for every node of
    // `splot.example.yml`, so any generator change shows up as a reviewable diff
    // of the generated router config (`cargo insta review`). It records today's
    // output as-is, known-wrong parts included: a fix shows up as a snapshot diff.
    // Keys are fakes; the pipeline's own delete/commit lines need uci and are
    // not part of it.

    #[test]
    fn example_config_snapshot() {
        let (config, network) = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));

        let managers: [(&str, &dyn UciManager); 3] = [
            ("network", &network::NetworkManager),
            ("firewall", &firewall::FirewallManager),
            ("dhcp", &dhcp::DhcpManager),
        ];

        let splot_config = SplotConfig::for_tests("FAKE_MESH_KEY");

        for (node_name, node) in &config.nodes {
            let context = NodeContext {
                own_name: node_name,
                own_node: node,
                splot_config: &splot_config,
            };

            let mut output = String::new();
            for (label, manager) in managers {
                writeln!(output, "# {label}").unwrap();
                for command in manager.generate_commands(&config, &network, &context) {
                    writeln!(output, "{command}").unwrap();
                }
            }

            insta::assert_snapshot!(format!("example_{node_name}"), output);
        }
    }

    struct Example {
        section_type: &'static str,
        id: Vec<String>,
    }

    impl UciSection for Example {
        const FILE: &'static str = "firewall";

        fn section_type(&self) -> &str {
            self.section_type
        }

        fn id(&self) -> impl IntoIterator<Item = &str> {
            self.id.iter().map(String::as_str)
        }

        fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
            section.set("target", "ACCEPT")
        }
    }

    fn example(section_type: &'static str, id: &[&str]) -> Example {
        Example {
            section_type,
            id: id.iter().map(|part| part.to_string()).collect(),
        }
    }

    #[test]
    fn section_is_named_after_its_type_and_id() {
        let cmds = example("rule", &["in", "my-printer_ipp"]).to_uci_commands();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            render(&cmds[0]),
            "set firewall.spl_rule_in_my_printer_ipp='rule'"
        );
        assert_eq!(
            render(&cmds[1]),
            "set firewall.spl_rule_in_my_printer_ipp.target='ACCEPT'"
        );
    }

    #[test]
    fn same_id_under_another_type_is_another_section() {
        // A rule and a redirect for the same service share their id; the type in
        // the name keeps uci from merging them.
        assert_ne!(
            example("rule", &["Home_ssh"]).section_name(),
            example("redirect", &["Home_ssh"]).section_name()
        );
    }

    fn builder() -> UciSectionBuilder {
        UciSectionBuilder::new("firewall", &UciSectionName::new(["my_rule"]), "rule")
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
