//! What turns a file's current splot sections into the rendered ones: only the
//! changes, so applying an unchanged config stages nothing.

use std::collections::{HashMap, HashSet};

use super::{
    section::{Section, Value},
    uci::UciBatchCommand,
};
use crate::consts;

fn is_splot(section: &Section) -> bool {
    section.name.starts_with(consts::SPLOT_SECTION_PREFIX)
}

/// The changes to one section's options: options it shouldn't have are deleted, a
/// changed value is set, a changed list is replaced as a whole.
fn option_changes(path: &str, current: &Section, desired: &Section) -> Vec<UciBatchCommand> {
    let mut commands = Vec::new();
    let value_of = |section: &Section, option: &str| {
        section
            .options
            .iter()
            .find(|(name, _)| name == option)
            .map(|(_, value)| value.clone())
    };

    for (option, _) in &current.options {
        if value_of(desired, option).is_none() {
            commands.push(UciBatchCommand::del(format!("{path}.{option}")));
        }
    }

    for (option, value) in &desired.options {
        let found = value_of(current, option);
        if found.as_ref() == Some(value) {
            continue;
        }

        let option = format!("{path}.{option}");
        match value {
            // `set` turns a list into a single value too.
            Value::Single(value) => commands.push(UciBatchCommand::set(option, value)),
            Value::List(values) => {
                if found.is_some() {
                    commands.push(UciBatchCommand::del(&option));
                }
                commands.extend(
                    values
                        .iter()
                        .map(|value| UciBatchCommand::add_list(&option, value)),
                );
            }
        }
    }

    commands
}

/// The commands that turn the splot sections of `file` (`current`, in file order)
/// into `desired`, leaving every other section alone. splot's sections end up as
/// one block after the operator's, in `desired`'s order.
pub(super) fn diff(file: &str, current: &[Section], desired: &[Section]) -> Vec<UciBatchCommand> {
    let path = |name: &str| format!("{file}.{name}");
    let found: HashMap<&str, &Section> = current
        .iter()
        .filter(|section| is_splot(section))
        .map(|section| (section.name.as_str(), section))
        .collect();
    let wanted: HashSet<&str> = desired
        .iter()
        .map(|section| section.name.as_str())
        .collect();

    let mut commands = Vec::new();
    // Sections that leave the file, and those created anew at its end.
    let mut removed = HashSet::new();
    let mut created = Vec::new();

    for section in current.iter().filter(|section| is_splot(section)) {
        if !wanted.contains(section.name.as_str()) {
            commands.push(UciBatchCommand::del(path(&section.name)));
            removed.insert(section.name.as_str());
        }
    }

    for section in desired {
        let name = section.name.as_str();

        match found.get(name) {
            Some(current) if current.section_type == section.section_type => {
                commands.extend(option_changes(&path(name), current, section));
            }
            Some(_) => {
                commands.push(UciBatchCommand::del(path(name)));
                commands.extend(section.commands(file));
                removed.insert(name);
                created.push(name);
            }
            None => {
                commands.extend(section.commands(file));
                created.push(name);
            }
        }
    }

    // The order the changes leave: what stays where it is, then what's created.
    let resulting: Vec<&str> = current
        .iter()
        .map(|section| section.name.as_str())
        .filter(|name| !removed.contains(name))
        .chain(created)
        .collect();
    let operators = current.iter().filter(|section| !is_splot(section));
    let ordered: Vec<&str> = operators
        .map(|section| section.name.as_str())
        .chain(desired.iter().map(|section| section.name.as_str()))
        .collect();

    // Out of order: move each splot section to the end, in turn.
    if resulting != ordered {
        let last = ordered.len().saturating_sub(1);
        commands.extend(
            desired
                .iter()
                .map(|section| UciBatchCommand::reorder(path(&section.name), last)),
        );
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::openwrt::export;

    /// One file's sections, written the way `uci export` prints them.
    const CURRENT: &str = "
config zone
	option name 'lan'

config rule 'spl_rule_in_Home_ssh'
	option name '[SPLOT] in: Home ssh'
	option dest_port '22'
	list src_ip '10.0.0.1/32'

config redirect 'spl_redirect_Home_nas_https'
	option name '[SPLOT] Home.nas https'
";

    fn sections(text: &str) -> Vec<Section> {
        export::parse(text).unwrap()
    }

    fn diff_to(desired: &str) -> Vec<String> {
        diff("firewall", &sections(CURRENT), &sections(desired))
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// CURRENT without the operator's zone: what splot renders.
    fn rendered() -> String {
        CURRENT.replace("config zone\n\toption name 'lan'\n", "")
    }

    #[test]
    fn nothing_changed_stages_nothing() {
        assert!(diff_to(&rendered()).is_empty());
    }

    #[test]
    fn a_changed_value_is_set() {
        assert_eq!(
            diff_to(&rendered().replace("'22'", "'2222'")),
            ["set firewall.spl_rule_in_Home_ssh.dest_port='2222'"]
        );
    }

    #[test]
    fn a_changed_list_is_replaced_whole() {
        assert_eq!(
            diff_to(&rendered().replace(
                "\tlist src_ip '10.0.0.1/32'\n",
                "\tlist src_ip '10.0.0.1/32'\n\tlist src_ip '10.0.0.2/32'\n"
            )),
            [
                "delete firewall.spl_rule_in_Home_ssh.src_ip",
                "add_list firewall.spl_rule_in_Home_ssh.src_ip='10.0.0.1/32'",
                "add_list firewall.spl_rule_in_Home_ssh.src_ip='10.0.0.2/32'",
            ]
        );
    }

    #[test]
    fn an_option_the_section_shouldnt_have_is_deleted() {
        assert_eq!(
            diff_to(&rendered().replace("\toption dest_port '22'\n", "")),
            ["delete firewall.spl_rule_in_Home_ssh.dest_port"]
        );
    }

    #[test]
    fn a_value_that_becomes_a_list_is_replaced() {
        // A one-value list differs from a single value, though `uci show` prints
        // both alike.
        assert_eq!(
            diff_to(&rendered().replace("option dest_port '22'", "list dest_port '22'")),
            [
                "delete firewall.spl_rule_in_Home_ssh.dest_port",
                "add_list firewall.spl_rule_in_Home_ssh.dest_port='22'",
            ]
        );
    }

    #[test]
    fn a_gone_section_is_deleted() {
        let without_redirect = rendered()
            .replace("config redirect 'spl_redirect_Home_nas_https'\n", "")
            .replace("\toption name '[SPLOT] Home.nas https'\n", "");
        assert_eq!(
            diff_to(&without_redirect),
            ["delete firewall.spl_redirect_Home_nas_https"]
        );
    }

    #[test]
    fn a_new_section_is_created_at_the_end() {
        let with_new = format!(
            "{}\nconfig rule 'spl_rule_in_Home_dns'\n\toption dest_port '53'\n",
            rendered()
        );
        assert_eq!(
            diff_to(&with_new),
            [
                "set firewall.spl_rule_in_Home_dns='rule'",
                "set firewall.spl_rule_in_Home_dns.dest_port='53'",
            ]
        );
    }

    #[test]
    fn a_new_section_in_the_middle_puts_the_block_in_order() {
        // The new rule belongs before the redirect, but uci creates it at the end:
        // every splot section moves to the end, in turn.
        let with_new = rendered().replace(
            "config redirect",
            "config rule 'spl_rule_in_Home_dns'\n\toption dest_port '53'\n\nconfig redirect",
        );
        assert_eq!(
            diff_to(&with_new),
            [
                "set firewall.spl_rule_in_Home_dns='rule'",
                "set firewall.spl_rule_in_Home_dns.dest_port='53'",
                "reorder firewall.spl_rule_in_Home_ssh=3",
                "reorder firewall.spl_rule_in_Home_dns=3",
                "reorder firewall.spl_redirect_Home_nas_https=3",
            ]
        );
    }

    #[test]
    fn a_section_whose_type_changed_is_recreated() {
        let as_redirect = rendered().replace(
            "config rule 'spl_rule_in_Home_ssh'",
            "config redirect 'spl_rule_in_Home_ssh'",
        );
        let commands = diff_to(&as_redirect);
        assert_eq!(commands[0], "delete firewall.spl_rule_in_Home_ssh");
        assert_eq!(commands[1], "set firewall.spl_rule_in_Home_ssh='redirect'");
    }

    #[test]
    fn an_operator_section_after_splots_puts_the_block_last_again() {
        let current = sections(&format!("{}\nconfig rule 'operator'\n", CURRENT));
        let commands: Vec<String> = diff("firewall", &current, &sections(&rendered()))
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            commands,
            [
                "reorder firewall.spl_rule_in_Home_ssh=3",
                "reorder firewall.spl_redirect_Home_nas_https=3",
            ]
        );
    }

    #[test]
    fn operator_sections_are_left_alone() {
        // splot renders none of them, and deletes none.
        let current = sections(&format!("{}\nconfig rule 'operator'\n", CURRENT));
        let commands = diff("firewall", &current, &[]);
        let touched: Vec<String> = commands.iter().map(ToString::to_string).collect();
        assert_eq!(
            touched,
            [
                "delete firewall.spl_rule_in_Home_ssh",
                "delete firewall.spl_redirect_Home_nas_https",
            ]
        );
    }
}
