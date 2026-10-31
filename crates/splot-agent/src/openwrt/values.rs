//! splot's values in the operator's dnsmasq sections: the `server` and
//! `rebind_domain` lists, where dnsmasq on OpenWrt reads them and nowhere
//! else. splot owns every value that names a mesh domain (or a name inside
//! one), whoever added it, and those it recorded adding, in an option of its
//! own beside them (`spl_server`, `spl_rebind_domain`; dnsmasq ignores them):
//! so it takes back a value for a domain that's gone. Every other value, and
//! the rest of the section, stays the operator's. https-dns-proxy, which
//! rewrites the `server` list, keeps values that name a domain.

use splot_core::{
    protocol::openwrt::DnsmasqValues,
    uci::section::{Section, Value},
};

use super::{diff::value_of, uci::UciBatchCommand};

/// The operator's dnsmasq sections' type.
const SECTION_TYPE: &str = "dnsmasq";

/// The domains `value` of `option` names: `/a/b/192.168.2.1` names `a` and
/// `b`, a `rebind_domain` value its domain; a plain upstream server none.
fn domains<'a>(option: &str, value: &'a str) -> Vec<&'a str> {
    match option {
        "server" if value.starts_with('/') => {
            let mut parts: Vec<&str> = value.split('/').collect();
            // The leading empty part, and what follows the last slash.
            parts.remove(0);
            parts.pop();
            parts.into_iter().filter(|part| !part.is_empty()).collect()
        }
        "server" => Vec::new(),
        _ => vec![value.trim_matches('/')],
    }
}

/// Whether `name` is `domain` or inside it, case aside.
fn within(name: &str, domain: &str) -> bool {
    let (name, domain) = (name.to_ascii_lowercase(), domain.to_ascii_lowercase());

    name == domain || name.ends_with(&format!(".{domain}"))
}

fn values(section: &Section, option: &str) -> Vec<String> {
    match value_of(section, option) {
        Some(Value::Single(value)) => vec![value.clone()],
        Some(Value::List(values)) => values.clone(),
        None => Vec::new(),
    }
}

/// The commands that make `option` of `section` (`path` in uci) hold
/// `desired` as splot's, and record them; none when it does already. The
/// operator's values keep their place, splot's new ones follow.
fn option_commands(
    path: &str,
    section: &Section,
    option: &str,
    desired: &[String],
    mesh_domains: &[String],
) -> Vec<UciBatchCommand> {
    let record = format!("spl_{option}");
    let present = values(section, option);
    let recorded = values(section, &record);
    let splots = |value: &String| {
        recorded.contains(value)
            || domains(option, value)
                .iter()
                .any(|name| mesh_domains.iter().any(|domain| within(name, domain)))
    };

    let mut wanted: Vec<String> = present
        .iter()
        .filter(|value| !splots(value) || desired.contains(value))
        .cloned()
        .collect();
    wanted.extend(
        desired
            .iter()
            .filter(|value| !present.contains(value))
            .cloned(),
    );

    let mut commands = Vec::new();
    for (option, now, then) in [
        (option, &present, &wanted),
        (record.as_str(), &recorded, &desired.to_vec()),
    ] {
        if now == then {
            continue;
        }
        let option = format!("{path}.{option}");
        if !now.is_empty() {
            commands.push(UciBatchCommand::del(&option));
        }
        commands.extend(
            then.iter()
                .map(|value| UciBatchCommand::add_list(&option, value)),
        );
    }

    commands
}

/// The commands that make each of the operator's dnsmasq sections in `current`
/// (`file`'s sections) hold `dnsmasq`'s values as splot's.
pub(super) fn commands(
    file: &str,
    current: &[Section],
    dnsmasq: &DnsmasqValues,
) -> Vec<UciBatchCommand> {
    current
        .iter()
        .filter(|section| section.section_type == SECTION_TYPE)
        .flat_map(|section| {
            let path = format!("{file}.{}", section.name);
            [
                ("server", &dnsmasq.server),
                ("rebind_domain", &dnsmasq.rebind_domain),
            ]
            .into_iter()
            .flat_map(move |(option, desired)| {
                option_commands(&path, section, option, desired, &dnsmasq.domains)
            })
            .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use splot_core::uci::export;

    use super::*;

    fn dnsmasq() -> DnsmasqValues {
        let strings = |values: &[&str]| values.iter().map(|value| value.to_string()).collect();
        DnsmasqValues {
            server: strings(&[
                "/home.example.org/",
                "/cabin.example.org/192.168.2.1",
                "/wg.cabin.example.org/#",
            ]),
            rebind_domain: strings(&["cabin.example.org"]),
            domains: strings(&["home.example.org", "cabin.example.org"]),
        }
    }

    /// The commands for the dhcp file whose dnsmasq section has `options`
    /// (lines as `uci export` prints them).
    fn commands_for(options: &str) -> Vec<String> {
        let current = export::parse(&format!(
            "config dnsmasq\n{options}\nconfig host 'spl_host_printer'\n\toption name 'printer'\n"
        ))
        .unwrap();
        commands("dhcp", &current, &dnsmasq())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn splots_values_follow_the_operators() {
        assert_eq!(
            commands_for("\tlist server '8.8.8.8'\n\toption domain 'lan'\n"),
            [
                "delete dhcp.@dnsmasq[0].server",
                "add_list dhcp.@dnsmasq[0].server='8.8.8.8'",
                "add_list dhcp.@dnsmasq[0].server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].server='/cabin.example.org/192.168.2.1'",
                "add_list dhcp.@dnsmasq[0].server='/wg.cabin.example.org/#'",
                "add_list dhcp.@dnsmasq[0].spl_server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].spl_server='/cabin.example.org/192.168.2.1'",
                "add_list dhcp.@dnsmasq[0].spl_server='/wg.cabin.example.org/#'",
                "add_list dhcp.@dnsmasq[0].rebind_domain='cabin.example.org'",
                "add_list dhcp.@dnsmasq[0].spl_rebind_domain='cabin.example.org'",
            ]
        );
    }

    #[test]
    fn values_in_place_change_nothing() {
        let options = "\tlist server '8.8.8.8'
\tlist server '/home.example.org/'
\tlist server '/cabin.example.org/192.168.2.1'
\tlist server '/wg.cabin.example.org/#'
\tlist spl_server '/home.example.org/'
\tlist spl_server '/cabin.example.org/192.168.2.1'
\tlist spl_server '/wg.cabin.example.org/#'
\tlist rebind_domain 'cabin.example.org'
\tlist spl_rebind_domain 'cabin.example.org'
";
        assert!(
            commands_for(options).is_empty(),
            "{:?}",
            commands_for(options)
        );
    }

    #[test]
    fn a_value_for_a_mesh_domain_is_splots_whoever_added_it() {
        // The operator's forward of Cabin's domain, by hand, to another
        // address: splot's address replaces it. Their own upstream stays.
        let options = "\tlist server '/cabin.example.org/10.0.0.53'
\tlist server '127.0.0.1#5053'
\tlist server '/home.example.org/'
\tlist server '/wg.cabin.example.org/#'
\tlist spl_server '/home.example.org/'
\tlist spl_server '/wg.cabin.example.org/#'
\tlist rebind_domain 'cabin.example.org'
\tlist spl_rebind_domain 'cabin.example.org'
";
        assert_eq!(
            commands_for(options),
            [
                "delete dhcp.@dnsmasq[0].server",
                "add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'",
                "add_list dhcp.@dnsmasq[0].server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].server='/wg.cabin.example.org/#'",
                "add_list dhcp.@dnsmasq[0].server='/cabin.example.org/192.168.2.1'",
                "delete dhcp.@dnsmasq[0].spl_server",
                "add_list dhcp.@dnsmasq[0].spl_server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].spl_server='/cabin.example.org/192.168.2.1'",
                "add_list dhcp.@dnsmasq[0].spl_server='/wg.cabin.example.org/#'",
            ]
        );
    }

    #[test]
    fn a_value_splot_recorded_is_taken_back_when_its_domain_is_gone() {
        // Lake's domain left the config; another of the operator's stays.
        let options = "\tlist server '/home.example.org/'
\tlist server '/cabin.example.org/192.168.2.1'
\tlist server '/wg.cabin.example.org/#'
\tlist server '/lake.example.org/192.168.3.1'
\tlist server '/corp.example.com/10.1.1.1'
\tlist spl_server '/home.example.org/'
\tlist spl_server '/cabin.example.org/192.168.2.1'
\tlist spl_server '/wg.cabin.example.org/#'
\tlist spl_server '/lake.example.org/192.168.3.1'
\tlist rebind_domain 'cabin.example.org'
\tlist rebind_domain 'lake.example.org'
\tlist spl_rebind_domain 'cabin.example.org'
\tlist spl_rebind_domain 'lake.example.org'
";
        assert_eq!(
            commands_for(options),
            [
                "delete dhcp.@dnsmasq[0].server",
                "add_list dhcp.@dnsmasq[0].server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].server='/cabin.example.org/192.168.2.1'",
                "add_list dhcp.@dnsmasq[0].server='/wg.cabin.example.org/#'",
                "add_list dhcp.@dnsmasq[0].server='/corp.example.com/10.1.1.1'",
                "delete dhcp.@dnsmasq[0].spl_server",
                "add_list dhcp.@dnsmasq[0].spl_server='/home.example.org/'",
                "add_list dhcp.@dnsmasq[0].spl_server='/cabin.example.org/192.168.2.1'",
                "add_list dhcp.@dnsmasq[0].spl_server='/wg.cabin.example.org/#'",
                "delete dhcp.@dnsmasq[0].rebind_domain",
                "add_list dhcp.@dnsmasq[0].rebind_domain='cabin.example.org'",
                "delete dhcp.@dnsmasq[0].spl_rebind_domain",
                "add_list dhcp.@dnsmasq[0].spl_rebind_domain='cabin.example.org'",
            ]
        );
    }

    #[test]
    fn an_operators_single_value_stays_in_a_list() {
        let commands: Vec<String> = commands_for("\toption rebind_domain 'corp.example.com'\n")
            .into_iter()
            .filter(|command| command.contains(".rebind_domain"))
            .collect();
        assert_eq!(
            commands,
            [
                "delete dhcp.@dnsmasq[0].rebind_domain",
                "add_list dhcp.@dnsmasq[0].rebind_domain='corp.example.com'",
                "add_list dhcp.@dnsmasq[0].rebind_domain='cabin.example.org'",
            ]
        );
    }

    #[test]
    fn what_a_value_names() {
        assert_eq!(
            domains("server", "/a.org/b.org/1.2.3.4"),
            ["a.org", "b.org"]
        );
        assert_eq!(domains("server", "/a.org/"), ["a.org"]);
        assert_eq!(domains("server", "/a.org/#"), ["a.org"]);
        assert!(domains("server", "8.8.8.8").is_empty());
        assert!(domains("server", "127.0.0.1#5053").is_empty());
        assert_eq!(domains("rebind_domain", "a.org"), ["a.org"]);
        assert_eq!(domains("rebind_domain", "/a.org/"), ["a.org"]);
    }
}
