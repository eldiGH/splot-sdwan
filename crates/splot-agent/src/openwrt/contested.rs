//! The operator's own sections in the firewall file that decide some of what
//! splot owns there: what the rendered config says splot decides. fw4 checks a
//! zone's rules before its forwardings, and the rules in the file's order, the
//! operator's before splot's: such a forwarding forwards nothing any more, and
//! such a rule decides before splot's do. What comes from any zone (`*`) is in
//! fw4's forward chain, ahead of every zone's own: a forwarding there accepts
//! first.

use std::fmt;

use splot_core::{
    identifier::Identifier,
    protocol::openwrt::{Crossing, Dest},
    uci::{
        naming,
        section::{Section, Value},
    },
};

use super::diff;

/// The uci file of the firewall.
pub(super) const FIREWALL: &str = "firewall";

/// fw4's name for any zone, in a section's `src` or `dest`.
const ANY_ZONE: &str = "*";

/// One of the operator's sections that decides some of what splot owns on
/// `node`: where it does (`crossings`), and how.
#[derive(Debug)]
pub(super) struct Contested<'a> {
    node: &'a Identifier,
    section: &'a Section,
    src: &'a str,
    kind: Kind,
    crossings: Vec<Crossing>,
}

/// What an operator's section does where splot decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A forwarding from one zone: fw4 checks splot's deny first.
    Shadowed,
    /// A rule that accepts, or a forwarding from any zone: before splot's
    /// deny.
    Accepts,
    /// A rule that drops or rejects: before splot's accepts.
    Drops,
    Rejects,
}

/// The operator's sections in `current` (the firewall file's, in order) that
/// decide some of what `owned` says splot decides on `node`.
pub(super) fn contested<'a>(
    node: &'a Identifier,
    current: &'a [Section],
    owned: &[Crossing],
) -> Vec<Contested<'a>> {
    current
        .iter()
        .filter(|section| !diff::is_splot(section) && enabled(section))
        .filter_map(|section| {
            let src = single(section, "src")?;
            let dest = single(section, "dest");
            let kind = match (section.section_type.as_str(), dest) {
                // fw4 takes no forwarding without a `dest`.
                ("forwarding", None) => return None,
                ("forwarding", _) if src == ANY_ZONE => Kind::Accepts,
                ("forwarding", _) => Kind::Shadowed,
                ("rule", _) => verdict(single(section, "target")?)?,
                _ => return None,
            };

            let crossings: Vec<Crossing> = owned
                .iter()
                .filter_map(|owned| overlap(owned, src, dest))
                .collect();

            (!crossings.is_empty()).then_some(Contested {
                node,
                section,
                src,
                kind,
                crossings,
            })
        })
        .collect()
}

/// `section`'s `option`, when it has one value.
fn single<'a>(section: &'a Section, option: &str) -> Option<&'a str> {
    match diff::value_of(section, option)? {
        Value::Single(value) => Some(value),
        Value::List(_) => None,
    }
}

/// Whether fw4 takes `section`: unless its `enabled` is something fw4 reads as
/// true, it skips the section.
fn enabled(section: &Section) -> bool {
    match diff::value_of(section, "enabled") {
        None => true,
        Some(Value::Single(value)) => ["1", "on", "true", "yes"].contains(&value.as_str()),
        Some(Value::List(_)) => false,
    }
}

/// What a rule with `target` does with what it matches, as fw4 reads a
/// target (in any case, any start of one, the first of fw4's that fits); none
/// for one that's no verdict.
fn verdict(target: &str) -> Option<Kind> {
    const TARGETS: [&str; 10] = [
        "accept",
        "reject",
        "drop",
        "notrack",
        "helper",
        "mark",
        "dscp",
        "dnat",
        "snat",
        "masquerade",
    ];
    let target = target.to_lowercase();

    match *TARGETS.iter().find(|known| known.starts_with(&target))? {
        "accept" => Some(Kind::Accepts),
        "reject" => Some(Kind::Rejects),
        "drop" => Some(Kind::Drops),
        _ => None,
    }
}

/// Where what goes from `src` to `dest` (to the node itself when none; `*`
/// any zone) is in `owned`; none when nowhere.
fn overlap(owned: &Crossing, src: &str, dest: Option<&str>) -> Option<Crossing> {
    if src != ANY_ZONE && src != owned.from {
        return None;
    }
    let to = match (dest, &owned.to) {
        (None, Dest::Node) => Dest::Node,
        (Some(ANY_ZONE), to @ (Dest::Zone(_) | Dest::AnyZone)) => to.clone(),
        (Some(dest), Dest::Zone(to)) if dest == to => Dest::Zone(to.clone()),
        (Some(dest), Dest::AnyZone) => Dest::Zone(dest.to_owned()),
        _ => return None,
    };

    Some(Crossing {
        from: owned.from.clone(),
        to,
    })
}

/// "from lan to iot", "from spl_mesh to any zone", "from spl_mesh to the
/// node".
fn described(crossing: &Crossing) -> String {
    let to = match &crossing.to {
        Dest::Zone(zone) => zone,
        Dest::AnyZone => "any zone",
        Dest::Node => "the node",
    };
    format!("from {} to {to}", crossing.from)
}

impl Contested<'_> {
    /// What `allowFrom` names the section's sources by, when they're one of
    /// the zones splot.yml declares: `Home.lan`.
    fn sources(&self) -> Option<String> {
        (self.src != ANY_ZONE && self.src != naming::mesh_interface().to_string())
            .then(|| format!("{}.{}", self.node, self.src))
    }
}

impl fmt::Display for Contested<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FIREWALL}.{}", self.section.name)?;
        if let Some(name) = single(self.section, "name") {
            write!(f, " ('{name}')")?;
        }
        let crossings: Vec<String> = self.crossings.iter().map(described).collect();
        let crossings = crossings.join(", ");
        let sources = self
            .sources()
            .map(|sources| format!(" (allowFrom: {sources})"))
            .unwrap_or_default();

        match self.kind {
            Kind::Shadowed => write!(
                f,
                " forwards nothing {crossings} any more: fw4 checks rules first, and splot drops what no service grants there. Declare what it carried as services{sources}."
            ),
            Kind::Accepts => write!(
                f,
                " accepts {crossings} before splot's rules, so what it matches gets through though no service grants it. Declare that as services{sources} instead."
            ),
            Kind::Drops | Kind::Rejects => {
                let verb = if self.kind == Kind::Drops {
                    "drops"
                } else {
                    "rejects"
                };
                write!(
                    f,
                    " {verb} {crossings} before splot's rules, so no service splot grants there gets through. Leave that to splot: it drops what no service grants."
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use splot_core::uci::export;

    use super::*;

    fn home() -> Identifier {
        "Home".parse().unwrap()
    }

    fn crossing(from: &str, to: Dest) -> Crossing {
        Crossing {
            from: from.to_owned(),
            to,
        }
    }

    fn zone(name: &str) -> Dest {
        Dest::Zone(name.to_owned())
    }

    /// What splot owns on a node with two zones of its own, lan and iot, and
    /// its mesh zone: what its deny drops, and the node's input from the mesh.
    fn owned() -> Vec<Crossing> {
        vec![
            crossing("spl_mesh", Dest::AnyZone),
            crossing("iot", zone("spl_mesh")),
            crossing("iot", zone("lan")),
            crossing("lan", zone("spl_mesh")),
            crossing("lan", zone("iot")),
            crossing("spl_mesh", Dest::Node),
        ]
    }

    /// The sections of `text` (written the way `uci export` prints them) that
    /// are found, by name, against `owned`.
    fn found_against(text: &str, owned: &[Crossing]) -> Vec<String> {
        let node = home();
        let sections = export::parse(text).unwrap();
        contested(&node, &sections, owned)
            .iter()
            .map(|contested| contested.section.name.clone())
            .collect()
    }

    fn found(text: &str) -> Vec<String> {
        found_against(text, &owned())
    }

    /// The warning for each section of `text` that's found.
    fn warnings(text: &str) -> Vec<String> {
        let node = home();
        let sections = export::parse(text).unwrap();
        contested(&node, &sections, &owned())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// A forwarding from `src` to `dest`.
    fn forwarding(src: &str, dest: &str) -> String {
        format!("\nconfig forwarding\n\toption src '{src}'\n\toption dest '{dest}'\n")
    }

    #[test]
    fn a_forwarding_splots_deny_drops_is_found() {
        let text = [
            forwarding("lan", "wan"),
            forwarding("lan", "spl_mesh"),
            forwarding("lan", "guest"),
            forwarding("iot", "lan"),
            forwarding("spl_mesh", "wan"),
            forwarding("wan", "spl_mesh"),
            forwarding("guest", "lan"),
            forwarding("lan", "lan"),
            // fw4 takes none without a dest.
            "\nconfig forwarding\n\toption src 'spl_mesh'\n".to_owned(),
        ]
        .concat();
        // Into the mesh from the WAN is left alone: no deny there. Nor between a
        // splot zone and one splot.yml doesn't declare, nor within a zone.
        assert_eq!(
            found(&text),
            ["@forwarding[1]", "@forwarding[3]", "@forwarding[4]"]
        );
    }

    #[test]
    fn only_what_splot_owns_on_the_node_is_found() {
        // Without a mesh zone of splot's (its WireGuard left alone), the zone
        // of that name isn't splot's.
        let declared = [crossing("iot", zone("lan")), crossing("lan", zone("iot"))];
        assert_eq!(
            found_against(
                &[forwarding("lan", "spl_mesh"), forwarding("lan", "iot")].concat(),
                &declared
            ),
            ["@forwarding[1]"]
        );
        // Where splot leaves the firewall alone, nothing.
        assert!(found_against(&forwarding("lan", "iot"), &[]).is_empty());
    }

    #[test]
    fn splots_own_sections_and_disabled_ones_are_not_found() {
        let text = "
config rule 'spl_rule_in_Home_tv_cast_from_lan'
	option src 'lan'
	option dest 'iot'
	option target 'ACCEPT'

config rule 'spl_rule_deny_lan_to_iot'
	option src 'lan'
	option dest 'iot'
	option target 'DROP'

config forwarding 'lan_iot'
	option src 'lan'
	option dest 'iot'
	option enabled '0'

config forwarding 'iot_lan'
	option src 'iot'
	option dest 'lan'
	option enabled 'no'

config forwarding 'lan_mesh'
	option src 'lan'
	option dest 'spl_mesh'
	option enabled 'yes'
";
        // fw4 skips a section `enabled` isn't true for.
        assert_eq!(found(text), ["lan_mesh"]);
    }

    /// A rule from `src` to `dest` (none: to the node itself) with `target`
    /// (none: no target).
    fn rule(src: Option<&str>, dest: Option<&str>, target: Option<&str>) -> String {
        let mut text = String::from("\nconfig rule\n");
        for (option, value) in [("src", src), ("dest", dest), ("target", target)] {
            if let Some(value) = value {
                text.push_str(&format!("\toption {option} '{value}'\n"));
            }
        }
        text
    }

    #[test]
    fn a_rule_with_a_verdict_where_splot_decides_is_found() {
        let text = [
            rule(Some("lan"), Some("iot"), Some("ACCEPT")),
            rule(Some("iot"), Some("lan"), Some("DROP")),
            rule(Some("lan"), Some("spl_mesh"), Some("REJECT")),
            // No verdict: fw4 only counts what it matches.
            rule(Some("lan"), Some("iot"), None),
            rule(Some("lan"), Some("iot"), Some("MARK")),
            rule(Some("lan"), Some("iot"), Some("NOTRACK")),
            // To the WAN, and from it into the mesh.
            rule(Some("lan"), Some("wan"), Some("DROP")),
            rule(Some("wan"), Some("spl_mesh"), Some("ACCEPT")),
            // fw4 reads a target in any case, and any start of one.
            rule(Some("iot"), Some("lan"), Some("accept")),
            rule(Some("iot"), Some("lan"), Some("rej")),
            rule(Some("iot"), Some("lan"), Some("d")),
        ]
        .concat();
        assert_eq!(
            found(&text),
            [
                "@rule[0]",
                "@rule[1]",
                "@rule[2]",
                "@rule[8]",
                "@rule[9]",
                "@rule[10]"
            ]
        );
    }

    #[test]
    fn a_rule_for_the_nodes_input_from_the_mesh_is_found() {
        let text = [
            rule(Some("spl_mesh"), None, Some("ACCEPT")),
            // Input from the operator's own zones is the operator's.
            rule(Some("lan"), None, Some("ACCEPT")),
            rule(Some("wan"), None, Some("ACCEPT")),
            // The node's output.
            rule(None, Some("spl_mesh"), Some("DROP")),
            // From any zone: the mesh too.
            rule(Some("*"), None, Some("ACCEPT")),
        ]
        .concat();
        assert_eq!(found(&text), ["@rule[0]", "@rule[4]"]);
    }

    #[test]
    fn any_zone_is_every_zone() {
        let text = [
            forwarding("*", "iot"),
            forwarding("lan", "*"),
            forwarding("wan", "*"),
            rule(Some("*"), Some("*"), Some("DROP")),
            rule(Some("guest"), Some("*"), Some("ACCEPT")),
        ]
        .concat();
        assert_eq!(
            found(&text),
            ["@forwarding[0]", "@forwarding[1]", "@rule[0]"]
        );
    }

    #[test]
    fn each_warning_says_what_the_section_does_where_and_what_to_do() {
        let text = [
            forwarding("lan", "spl_mesh"),
            forwarding("spl_mesh", "wan"),
            forwarding("*", "iot"),
            "\nconfig rule\n\toption name 'Allow-Cast'\n\toption src 'lan'\n\toption dest 'iot'\n\toption target 'ACCEPT'\n".to_owned(),
            rule(Some("iot"), Some("lan"), Some("DROP")),
            rule(Some("lan"), Some("*"), Some("REJECT")),
            rule(Some("spl_mesh"), None, Some("ACCEPT")),
        ]
        .concat();
        assert_eq!(
            warnings(&text),
            [
                "firewall.@forwarding[0] forwards nothing from lan to spl_mesh any more: fw4 checks rules first, and splot drops what no service grants there. Declare what it carried as services (allowFrom: Home.lan).",
                "firewall.@forwarding[1] forwards nothing from spl_mesh to wan any more: fw4 checks rules first, and splot drops what no service grants there. Declare what it carried as services.",
                "firewall.@forwarding[2] accepts from spl_mesh to iot, from lan to iot before splot's rules, so what it matches gets through though no service grants it. Declare that as services instead.",
                "firewall.@rule[0] ('Allow-Cast') accepts from lan to iot before splot's rules, so what it matches gets through though no service grants it. Declare that as services (allowFrom: Home.lan) instead.",
                "firewall.@rule[1] drops from iot to lan before splot's rules, so no service splot grants there gets through. Leave that to splot: it drops what no service grants.",
                "firewall.@rule[2] rejects from lan to spl_mesh, from lan to iot before splot's rules, so no service splot grants there gets through. Leave that to splot: it drops what no service grants.",
                "firewall.@rule[3] accepts from spl_mesh to the node before splot's rules, so what it matches gets through though no service grants it. Declare that as services instead.",
            ]
        );
    }
}
