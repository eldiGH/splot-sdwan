//! What turns a file's current splot sections into the rendered ones: only the
//! changes, so applying an unchanged config stages nothing. `diff` finds them;
//! `commands` spells them in uci, right before they're staged.

use std::collections::{HashMap, HashSet};

use super::{
    section::{Section, Value},
    uci::UciBatchCommand,
};
use crate::consts;

/// One difference between a file's current splot sections and the rendered ones.
/// It points at the sections it's about: the rendered one where there is one, the
/// current one for what goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Change<'a> {
    /// A section splot no longer renders, or whose type changed (it's added anew).
    RemoveSection(&'a Section),
    AddSection(&'a Section),
    /// An option takes a value or list it didn't have, or a new one.
    SetOption {
        section: &'a Section,
        option: &'a str,
        old: Option<&'a Value>,
        new: &'a Value,
    },
    RemoveOption {
        section: &'a Section,
        option: &'a str,
        old: &'a Value,
    },
    /// splot's sections, in plan order, become the last in the file.
    Reorder(Vec<&'a Section>),
}

fn is_splot(section: &Section) -> bool {
    section.name.starts_with(consts::SPLOT_SECTION_PREFIX)
}

fn value_of<'a>(section: &'a Section, option: &str) -> Option<&'a Value> {
    section
        .options
        .iter()
        .find(|(name, _)| name == option)
        .map(|(_, value)| value)
}

/// The changes to one section's options, `desired` being the section rendered.
fn option_changes<'a>(current: &'a Section, desired: &'a Section) -> Vec<Change<'a>> {
    let mut changes = Vec::new();

    for (option, old) in &current.options {
        if value_of(desired, option).is_none() {
            changes.push(Change::RemoveOption {
                section: desired,
                option,
                old,
            });
        }
    }

    for (option, new) in &desired.options {
        let old = value_of(current, option);

        if old != Some(new) {
            changes.push(Change::SetOption {
                section: desired,
                option,
                old,
                new,
            });
        }
    }

    changes
}

/// What turns the splot sections in `current` (a file's sections, in file order)
/// into `desired`, leaving every other section alone. splot's sections end up as
/// one block after the operator's, in `desired`'s order.
pub(super) fn diff<'a>(current: &'a [Section], desired: &'a [Section]) -> Vec<Change<'a>> {
    let found: HashMap<&str, &Section> = current
        .iter()
        .filter(|section| is_splot(section))
        .map(|section| (section.name.as_str(), section))
        .collect();
    let wanted: HashSet<&str> = desired
        .iter()
        .map(|section| section.name.as_str())
        .collect();

    let mut changes = Vec::new();
    // Sections that leave the file, and those added anew at its end.
    let mut removed = HashSet::new();
    let mut added = Vec::new();

    for section in current.iter().filter(|section| is_splot(section)) {
        if !wanted.contains(section.name.as_str()) {
            changes.push(Change::RemoveSection(section));
            removed.insert(section.name.as_str());
        }
    }

    for section in desired {
        let name = section.name.as_str();

        match found.get(name) {
            Some(current) if current.section_type == section.section_type => {
                changes.extend(option_changes(current, section));
            }
            Some(current) => {
                changes.push(Change::RemoveSection(current));
                changes.push(Change::AddSection(section));
                removed.insert(name);
                added.push(name);
            }
            None => {
                changes.push(Change::AddSection(section));
                added.push(name);
            }
        }
    }

    // The order the changes leave: what stays where it is, then what's added.
    let resulting: Vec<&str> = current
        .iter()
        .map(|section| section.name.as_str())
        .filter(|name| !removed.contains(name))
        .chain(added)
        .collect();
    let operators = current.iter().filter(|section| !is_splot(section));
    let ordered: Vec<&str> = operators
        .map(|section| section.name.as_str())
        .chain(desired.iter().map(|section| section.name.as_str()))
        .collect();

    if resulting != ordered {
        changes.push(Change::Reorder(desired.iter().collect()));
    }

    changes
}

/// The file's last position once `changes` apply to its `current` sections: added
/// sections come at the end, removed ones leave.
fn last_position(current: &[Section], changes: &[Change]) -> usize {
    let count = |kind: fn(&Change) -> bool| changes.iter().filter(|change| kind(change)).count();
    let added = count(|change| matches!(change, Change::AddSection(_)));
    let removed = count(|change| matches!(change, Change::RemoveSection(_)));

    (current.len() + added).saturating_sub(removed + 1)
}

/// The uci commands that make `changes` to `file`, whose sections are now
/// `current`: the one place that knows how uci spells them.
pub(super) fn commands(
    file: &str,
    current: &[Section],
    changes: &[Change],
) -> Vec<UciBatchCommand> {
    let path = |section: &Section| format!("{file}.{}", section.name);
    let mut commands = Vec::new();

    for change in changes {
        match change {
            Change::RemoveSection(section) => commands.push(UciBatchCommand::del(path(section))),
            Change::AddSection(section) => commands.extend(section.commands(file)),
            Change::SetOption {
                section,
                option,
                old,
                new,
            } => {
                let option = format!("{}.{option}", path(section));

                match new {
                    // `set` turns a list into a single value too.
                    Value::Single(value) => commands.push(UciBatchCommand::set(option, value)),
                    Value::List(values) => {
                        // `add_list` appends: what was there goes first.
                        if old.is_some() {
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
            Change::RemoveOption {
                section, option, ..
            } => commands.push(UciBatchCommand::del(format!("{}.{option}", path(section)))),
            // Each section, in plan order, moves to the end: whatever the order
            // before, they end up last and in order, and the operator's sections
            // keep theirs. (Inserting each at the block's start, last to first, goes
            // wrong while a splot section still sits before an operator's.) uci's
            // `reorder` takes a position, read as a signed int: the real last one,
            // since `-1` or a too large number would move the section to the front.
            Change::Reorder(order) => {
                let last = last_position(current, changes);

                commands.extend(
                    order
                        .iter()
                        .map(|section| UciBatchCommand::reorder(path(section), last)),
                );
            }
        }
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

    /// CURRENT without the operator's zone: what splot renders.
    fn rendered() -> String {
        CURRENT.replace("config zone\n\toption name 'lan'\n", "")
    }

    fn value(value: &Value) -> String {
        match value {
            Value::Single(value) => format!("'{value}'"),
            Value::List(values) => format!("{values:?}"),
        }
    }

    /// A change in a few words, without uci's spelling.
    fn describe(change: &Change) -> String {
        match change {
            Change::RemoveSection(section) => format!("remove {}", section.name),
            Change::AddSection(section) => format!("add {}", section.name),
            Change::SetOption {
                section,
                option,
                old,
                new,
            } => format!(
                "set {}.{option}: {} -> {}",
                section.name,
                old.map_or("none".to_owned(), value),
                value(new)
            ),
            Change::RemoveOption {
                section,
                option,
                old,
            } => format!("remove {}.{option} ({})", section.name, value(old)),
            Change::Reorder(order) => {
                let names: Vec<&str> = order.iter().map(|section| section.name.as_str()).collect();
                format!("reorder {names:?}")
            }
        }
    }

    /// The changes from CURRENT to `desired`, described.
    fn changes_to(desired: &str) -> Vec<String> {
        let (current, desired) = (sections(CURRENT), sections(desired));
        diff(&current, &desired).iter().map(describe).collect()
    }

    #[test]
    fn nothing_changed_is_no_change() {
        assert!(changes_to(&rendered()).is_empty());
    }

    #[test]
    fn a_changed_value() {
        assert_eq!(
            changes_to(&rendered().replace("'22'", "'2222'")),
            ["set spl_rule_in_Home_ssh.dest_port: '22' -> '2222'"]
        );
    }

    #[test]
    fn a_changed_list() {
        assert_eq!(
            changes_to(&rendered().replace(
                "\tlist src_ip '10.0.0.1/32'\n",
                "\tlist src_ip '10.0.0.1/32'\n\tlist src_ip '10.0.0.2/32'\n"
            )),
            [
                r#"set spl_rule_in_Home_ssh.src_ip: ["10.0.0.1/32"] -> ["10.0.0.1/32", "10.0.0.2/32"]"#
            ]
        );
    }

    #[test]
    fn an_option_the_section_shouldnt_have() {
        assert_eq!(
            changes_to(&rendered().replace("\toption dest_port '22'\n", "")),
            ["remove spl_rule_in_Home_ssh.dest_port ('22')"]
        );
    }

    #[test]
    fn a_value_that_becomes_a_list() {
        // A one-value list differs from a single value, though `uci show` prints
        // both alike.
        assert_eq!(
            changes_to(&rendered().replace("option dest_port '22'", "list dest_port '22'")),
            [r#"set spl_rule_in_Home_ssh.dest_port: '22' -> ["22"]"#]
        );
    }

    #[test]
    fn a_gone_section() {
        let without_redirect = rendered()
            .replace("config redirect 'spl_redirect_Home_nas_https'\n", "")
            .replace("\toption name '[SPLOT] Home.nas https'\n", "");
        assert_eq!(
            changes_to(&without_redirect),
            ["remove spl_redirect_Home_nas_https"]
        );
    }

    #[test]
    fn a_new_section_at_the_end() {
        let with_new = format!(
            "{}\nconfig rule 'spl_rule_in_Home_dns'\n\toption dest_port '53'\n",
            rendered()
        );
        assert_eq!(changes_to(&with_new), ["add spl_rule_in_Home_dns"]);
    }

    #[test]
    fn a_new_section_in_the_middle_reorders_the_block() {
        // The new rule belongs before the redirect, but it's added at the end.
        let with_new = rendered().replace(
            "config redirect",
            "config rule 'spl_rule_in_Home_dns'\n\toption dest_port '53'\n\nconfig redirect",
        );
        assert_eq!(
            changes_to(&with_new),
            [
                "add spl_rule_in_Home_dns",
                r#"reorder ["spl_rule_in_Home_ssh", "spl_rule_in_Home_dns", "spl_redirect_Home_nas_https"]"#,
            ]
        );
    }

    #[test]
    fn a_section_whose_type_changed_is_added_anew() {
        let as_redirect = rendered().replace(
            "config rule 'spl_rule_in_Home_ssh'",
            "config redirect 'spl_rule_in_Home_ssh'",
        );
        let changes = changes_to(&as_redirect);
        assert_eq!(
            changes[..2],
            ["remove spl_rule_in_Home_ssh", "add spl_rule_in_Home_ssh"]
        );
    }

    #[test]
    fn an_operator_section_after_splots_reorders_the_block() {
        let current = sections(&format!("{CURRENT}\nconfig rule 'operator'\n"));
        let desired = sections(&rendered());
        let changes: Vec<String> = diff(&current, &desired).iter().map(describe).collect();
        assert_eq!(
            changes,
            [r#"reorder ["spl_rule_in_Home_ssh", "spl_redirect_Home_nas_https"]"#]
        );
    }

    #[test]
    fn operator_sections_are_left_alone() {
        // splot renders none of them, and removes none.
        let current = sections(&format!("{CURRENT}\nconfig rule 'operator'\n"));
        let changes: Vec<String> = diff(&current, &[]).iter().map(describe).collect();
        assert_eq!(
            changes,
            [
                "remove spl_rule_in_Home_ssh",
                "remove spl_redirect_Home_nas_https"
            ]
        );
    }

    // ── How uci spells the changes ─────────────────────────────────────────

    /// A section with one option.
    fn section(option: &str, value: Value) -> Section {
        Section {
            name: "spl_x".to_owned(),
            section_type: "rule".to_owned(),
            options: vec![(option.to_owned(), value)],
        }
    }

    fn list(values: &[&str]) -> Value {
        Value::List(values.iter().map(|value| value.to_string()).collect())
    }

    /// The changes as commands in a file with no sections yet.
    fn spelled(changes: &[Change]) -> Vec<String> {
        spelled_in(&[], changes)
    }

    fn spelled_in(current: &[Section], changes: &[Change]) -> Vec<String> {
        commands("firewall", current, changes)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_list_replaces_what_the_option_had() {
        let x = section("src_ip", list(&["a", "b"]));
        let new = &x.options[0].1;
        let old = Value::Single("z".to_owned());

        assert_eq!(
            spelled(&[Change::SetOption {
                section: &x,
                option: "src_ip",
                old: Some(&old),
                new,
            }]),
            [
                "delete firewall.spl_x.src_ip",
                "add_list firewall.spl_x.src_ip='a'",
                "add_list firewall.spl_x.src_ip='b'",
            ]
        );
        // Nothing there yet: nothing to delete.
        assert_eq!(
            spelled(&[Change::SetOption {
                section: &x,
                option: "src_ip",
                old: None,
                new,
            }]),
            [
                "add_list firewall.spl_x.src_ip='a'",
                "add_list firewall.spl_x.src_ip='b'",
            ]
        );
    }

    #[test]
    fn a_single_value_is_set_whatever_was_there() {
        let x = section("dest_port", Value::Single("22".to_owned()));
        let old = list(&["21"]);

        assert_eq!(
            spelled(&[Change::SetOption {
                section: &x,
                option: "dest_port",
                old: Some(&old),
                new: &x.options[0].1,
            }]),
            ["set firewall.spl_x.dest_port='22'"]
        );
    }

    #[test]
    fn sections_and_options_are_added_and_removed() {
        let x = section("dest_port", Value::Single("22".to_owned()));

        assert_eq!(
            spelled(&[
                Change::RemoveSection(&x),
                Change::AddSection(&x),
                Change::RemoveOption {
                    section: &x,
                    option: "dest_port",
                    old: &x.options[0].1,
                },
            ]),
            [
                "delete firewall.spl_x",
                "set firewall.spl_x='rule'",
                "set firewall.spl_x.dest_port='22'",
                "delete firewall.spl_x.dest_port",
            ]
        );
    }

    /// A section with no options.
    fn named(name: &str) -> Section {
        Section {
            name: name.to_owned(),
            section_type: "rule".to_owned(),
            options: Vec::new(),
        }
    }

    #[test]
    fn a_reorder_moves_each_section_to_the_end_in_plan_order() {
        // The file holds the operator's rule, x and y; z is added.
        let current = [named("operator"), named("spl_x"), named("spl_y")];
        let z = named("spl_z");

        assert_eq!(
            spelled_in(
                &current,
                &[
                    Change::AddSection(&z),
                    Change::Reorder(vec![&current[1], &z, &current[2]]),
                ]
            ),
            [
                "set firewall.spl_z='rule'",
                "reorder firewall.spl_x=3",
                "reorder firewall.spl_z=3",
                "reorder firewall.spl_y=3",
            ]
        );
    }

    #[test]
    fn the_last_position_counts_what_the_changes_add_and_remove() {
        let current = [named("operator"), named("spl_x"), named("spl_y")];
        let z = named("spl_z");
        let last = |changes: &[Change]| last_position(&current, changes);

        assert_eq!(last(&[]), 2);
        assert_eq!(last(&[Change::AddSection(&z)]), 3);
        assert_eq!(last(&[Change::RemoveSection(&current[2])]), 1);
        // A section whose type changed goes and comes back.
        assert_eq!(
            last(&[
                Change::RemoveSection(&current[1]),
                Change::AddSection(&current[1])
            ]),
            2
        );
        // An empty file.
        assert_eq!(last_position(&[], &[]), 0);
    }
}
