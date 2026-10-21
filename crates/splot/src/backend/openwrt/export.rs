//! Reading a uci file as `uci export` prints it. Not `uci show`: it prints a list
//! with one value exactly like an option, and the diff needs to tell them apart.

use super::section::{Section, Value};

#[derive(Debug, thiserror::Error)]
#[error("line {line}: {reason}")]
pub struct ParseError {
    line: usize,
    reason: &'static str,
}

/// One statement's words, and the line it starts on.
type Statement = (usize, Vec<String>);

/// Splits the text into statements: one per line, except that a quoted value may
/// span lines. Words are separated by whitespace; quoted parts and `\`-escaped
/// characters join the word they're in, which is how `'it'\''s'` reads `it's`.
fn statements(text: &str) -> Result<Vec<Statement>, ParseError> {
    let mut statements = Vec::new();
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars();

    while let Some(char) = chars.next() {
        match char {
            '\'' => {
                let word = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(char) => {
                            line += usize::from(char == '\n');
                            word.push(char);
                        }
                        None => {
                            return Err(ParseError {
                                line,
                                reason: "a quoted value isn't closed",
                            });
                        }
                    }
                }
            }
            '\\' => match chars.next() {
                Some(escaped) => word.get_or_insert_with(String::new).push(escaped),
                None => {
                    return Err(ParseError {
                        line,
                        reason: "the text ends after a `\\`",
                    });
                }
            },
            '\n' => {
                words.extend(word.take());
                if !words.is_empty() {
                    statements.push((start, std::mem::take(&mut words)));
                }
                line += 1;
                start = line;
            }
            char if char.is_whitespace() => words.extend(word.take()),
            char => word.get_or_insert_with(String::new).push(char),
        }
    }

    words.extend(word.take());
    if !words.is_empty() {
        statements.push((start, words));
    }

    Ok(statements)
}

/// The file's sections, in order. An anonymous section is named the way `uci show`
/// names it, `@<type>[<n>]`, `n` counting every section of its type before it: it
/// can't clash with a named one.
pub(super) fn parse(text: &str) -> Result<Vec<Section>, ParseError> {
    let mut sections: Vec<Section> = Vec::new();

    for (line, words) in statements(text)? {
        let error = |reason| ParseError { line, reason };

        match words.as_slice() {
            [keyword, _] if keyword == "package" => {}
            [keyword, section_type, rest @ ..] if keyword == "config" && rest.len() <= 1 => {
                let name = match rest {
                    [name] => name.clone(),
                    _ => {
                        let n = sections
                            .iter()
                            .filter(|section| section.section_type == *section_type)
                            .count();
                        format!("@{section_type}[{n}]")
                    }
                };

                sections.push(Section {
                    name,
                    section_type: section_type.clone(),
                    options: Vec::new(),
                });
            }
            [keyword, option, value] if keyword == "option" || keyword == "list" => {
                let section = sections
                    .last_mut()
                    .ok_or(error("an option before any section"))?;
                let existing = section.options.iter_mut().find(|(name, _)| name == option);

                match (keyword.as_str(), existing) {
                    ("option", None) => section
                        .options
                        .push((option.clone(), Value::Single(value.clone()))),
                    ("list", None) => section
                        .options
                        .push((option.clone(), Value::List(vec![value.clone()]))),
                    ("list", Some((_, Value::List(values)))) => values.push(value.clone()),
                    _ => return Err(error("an option given twice")),
                }
            }
            _ => return Err(error("not a `package`, `config`, `option` or `list` line")),
        }
    }

    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(value: &str) -> Value {
        Value::Single(value.to_owned())
    }

    fn list(values: &[&str]) -> Value {
        Value::List(values.iter().map(|value| value.to_string()).collect())
    }

    fn section(name: &str, section_type: &str, options: Vec<(&str, Value)>) -> Section {
        Section {
            name: name.to_owned(),
            section_type: section_type.to_owned(),
            options: options
                .into_iter()
                .map(|(option, value)| (option.to_owned(), value))
                .collect(),
        }
    }

    #[test]
    fn reads_sections_options_and_lists() {
        // As `uci export firewall` prints it.
        let sections = parse(
            "package firewall

config zone
	option name 'lan'
	list network 'lan'

config rule 'spl_rule_in_Home_ssh'
	option name '[SPLOT] in: Home ssh'
	list src_ip '10.0.0.1/32'
	list src_ip '10.0.0.2/32'
",
        )
        .unwrap();

        assert_eq!(
            sections,
            [
                section(
                    "@zone[0]",
                    "zone",
                    vec![("name", single("lan")), ("network", list(&["lan"]))]
                ),
                section(
                    "spl_rule_in_Home_ssh",
                    "rule",
                    vec![
                        ("name", single("[SPLOT] in: Home ssh")),
                        ("src_ip", list(&["10.0.0.1/32", "10.0.0.2/32"])),
                    ]
                ),
            ]
        );
    }

    #[test]
    fn a_one_value_list_stays_a_list() {
        // What `uci show` can't tell apart.
        let sections = parse("config zone\n\toption name 'lan'\n\tlist network 'lan'\n").unwrap();
        assert_eq!(sections[0].options[0].1, single("lan"));
        assert_eq!(sections[0].options[1].1, list(&["lan"]));
    }

    #[test]
    fn quotes_and_line_breaks_in_values() {
        let sections = parse(
            "config rule 'spl_x'
	option quote 'it'\\''s'
	option lines 'a
b'
	option empty ''
",
        )
        .unwrap();

        assert_eq!(
            sections[0].options,
            [
                ("quote".to_owned(), single("it's")),
                ("lines".to_owned(), single("a\nb")),
                ("empty".to_owned(), single("")),
            ]
        );
    }

    #[test]
    fn anonymous_sections_are_named_by_type_and_index() {
        let names: Vec<String> = parse(
            "config rule\n\
             config rule 'named'\n\
             config zone\n\
             config rule\n",
        )
        .unwrap()
        .into_iter()
        .map(|section| section.name)
        .collect();

        assert_eq!(names, ["@rule[0]", "named", "@zone[0]", "@rule[2]"]);
    }

    #[test]
    fn what_isnt_uci_export_is_an_error() {
        for text in [
            "option name 'x'\n",
            "config rule 'x'\n\toption name 'unclosed\n",
            "config rule 'x'\n\tbogus name 'x'\n",
            "config rule 'x'\n\toption name 'a'\n\toption name 'b'\n",
            "config rule 'x'\n\toption name 'a'\n\tlist name 'b'\n",
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }
}
