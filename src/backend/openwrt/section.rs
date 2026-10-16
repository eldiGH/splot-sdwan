//! A generated object as one uci section: its section name, its type and its
//! options.

use std::{fmt::Display, iter};

use super::{naming::UciSectionName, uci::UciBatchCommand};

/// An option's value: one value, or a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    Single(String),
    List(Vec<String>),
}

/// A uci section: its name, its type and its options, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Section {
    pub(super) name: String,
    pub(super) section_type: String,
    pub(super) options: Vec<(String, Value)>,
}

impl Section {
    /// The commands that create it in `file`: the section, then each option.
    pub(super) fn commands(&self, file: &str) -> Vec<UciBatchCommand> {
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

/// A generated object as one uci section. Its section name follows from what it
/// is: `spl_<section type>_<id>`.
pub(super) trait UciSection {
    /// The uci section type (`rule`, `redirect`, `host`, …). It also leads the
    /// section name: uci has one namespace per file, and the type keeps sections
    /// of different types apart.
    fn section_type(&self) -> &str;

    /// What tells this section apart from other sections of the same type.
    fn id(&self) -> impl IntoIterator<Item = &str>;

    /// Everything but the section's name and type.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder;

    fn section_name(&self) -> UciSectionName {
        UciSectionName::new(iter::once(self.section_type()).chain(self.id()))
    }

    fn to_section(&self) -> Section {
        let section = UciSectionBuilder::new(&self.section_name(), self.section_type());

        self.options(section).build()
    }
}

pub(super) struct UciSectionBuilder {
    section: Section,
}

impl UciSectionBuilder {
    pub(super) fn new(name: &UciSectionName, section_type: &str) -> Self {
        Self {
            section: Section {
                name: name.to_string(),
                section_type: section_type.to_owned(),
                options: Vec::new(),
            },
        }
    }

    pub(super) fn set(mut self, prop_name: &str, value: impl Into<String>) -> Self {
        self.section
            .options
            .push((prop_name.to_owned(), Value::Single(value.into())));

        self
    }

    pub(super) fn set_if_some(self, prop_name: &str, value: Option<impl Into<String>>) -> Self {
        let Some(value) = value else { return self };

        self.set(prop_name, value)
    }

    /// The values, sorted. An empty list adds no option.
    pub(super) fn extend_list(
        mut self,
        prop_name: &str,
        values: impl IntoIterator<Item = impl Display>,
    ) -> Self {
        let mut values: Vec<String> = values.into_iter().map(|v| v.to_string()).collect();
        values.sort();

        if !values.is_empty() {
            self.section
                .options
                .push((prop_name.to_owned(), Value::List(values)));
        }

        self
    }

    pub(super) fn build(self) -> Section {
        self.section
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(cmd: &UciBatchCommand) -> String {
        cmd.to_string()
    }

    struct Example {
        section_type: &'static str,
        id: Vec<String>,
    }

    impl UciSection for Example {
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
        let cmds = example("rule", &["in", "my-printer_ipp"])
            .to_section()
            .commands("firewall");
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
        UciSectionBuilder::new(&UciSectionName::new(["my_rule"]), "rule")
    }

    /// What the builder built, as commands in the firewall file.
    fn commands(builder: UciSectionBuilder) -> Vec<UciBatchCommand> {
        builder.build().commands("firewall")
    }

    #[test]
    fn new_emits_set_section_first() {
        let cmds = commands(builder());
        assert_eq!(cmds.len(), 1);
        // path is file.spl_<name>, value is the section type
        assert_eq!(render(&cmds[0]), "set firewall.spl_my_rule='rule'");
    }

    #[test]
    fn set_appends_property() {
        let cmds = commands(builder().set("dest", "lan"));
        assert_eq!(cmds.len(), 2);
        assert_eq!(render(&cmds[1]), "set firewall.spl_my_rule.dest='lan'");
    }

    #[test]
    fn set_if_some_emits_when_some() {
        let cmds = commands(builder().set_if_some("name", Some("hello")));
        assert_eq!(cmds.len(), 2);
        assert_eq!(render(&cmds[1]), "set firewall.spl_my_rule.name='hello'");
    }

    #[test]
    fn set_if_some_skips_when_none() {
        let cmds = commands(builder().set_if_some("name", None::<String>));
        // only the initial section set
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn extend_list_sorted_output() {
        // Pass values in reverse order; expect them sorted alphabetically in the output.
        let cmds = commands(
            builder().extend_list("src_ip", ["10.0.1.0/24", "10.0.0.0/24", "192.168.0.0/16"]),
        );
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
        let cmds = commands(builder().extend_list("src_ip", std::iter::empty::<String>()));
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn build_preserves_insertion_order() {
        let cmds = commands(
            builder()
                .set("target", "ACCEPT")
                .set("src", "mesh")
                .extend_list("proto", ["tcp", "udp"]),
        );
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
