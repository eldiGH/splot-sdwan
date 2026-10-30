//! splot's default policy as uci `rule` sections, after its accepts.

use splot_core::protocol::openwrt::{Crossing, Dest};

use super::{target, zone_name};
use crate::{
    backend::openwrt::{
        naming,
        section::{UciSection, UciSectionBuilder},
    },
    plan::firewall::{DefaultPolicy, Verdict, zone_ref::ZoneRef},
};

/// What goes from `from` to `to` (to any zone when none) that no rule accepted.
pub(super) struct Deny<'a> {
    from: &'a ZoneRef,
    to: Option<&'a ZoneRef>,
    verdict: Verdict,
}

/// fw4 applies a zone's `forward` policy only within the zone, so the default
/// policy takes rules, one for each crossing it covers. fw4 puts each in its
/// source zone's forward chain, in the order of the file, and the agent keeps
/// splot's sections in plan order: these come after splot's accepts.
pub(super) fn denies(policy: &DefaultPolicy) -> Vec<Deny<'_>> {
    policy
        .crossings()
        .into_iter()
        .map(|(from, to)| Deny {
            from,
            to,
            verdict: policy.verdict,
        })
        .collect()
}

impl Deny<'_> {
    /// What it drops, as fw4 names the zones.
    pub(super) fn crossing(&self) -> Crossing {
        Crossing {
            from: zone_name(self.from).to_owned(),
            to: self
                .to
                .map_or(Dest::AnyZone, |to| Dest::Zone(zone_name(to).to_owned())),
        }
    }
}

impl UciSection for Deny<'_> {
    fn section_type(&self) -> &str {
        "rule"
    }

    /// Not a service's: their ids begin with their direction.
    fn id(&self) -> impl IntoIterator<Item = &str> {
        let to = self.to.map_or("any", zone_name);
        ["deny", zone_name(self.from), "to", to]
    }

    /// Every protocol: without a `proto`, fw4 matches TCP and UDP alone.
    fn options(&self, section: UciSectionBuilder) -> UciSectionBuilder {
        let from = zone_name(self.from);
        let label = match self.to {
            Some(to) => format!("deny: {from} to {}", zone_name(to)),
            None => format!("deny: {from} to any zone"),
        };

        section
            .set("name", naming::name_prefixed(&label))
            .set("src", from)
            .set("dest", self.to.map_or("*", zone_name))
            .set("proto", "all")
            .set("target", target(self.verdict))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn named(zone: &str) -> ZoneRef {
        ZoneRef::Named(zone.parse().unwrap())
    }

    fn policy(zones: impl IntoIterator<Item = ZoneRef>) -> DefaultPolicy {
        DefaultPolicy {
            zones: BTreeSet::from_iter(zones),
            verdict: Verdict::Drop,
        }
    }

    fn commands(deny: &Deny) -> Vec<String> {
        deny.to_section()
            .commands("firewall")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Each deny's source and destination zone, as fw4 knows them.
    fn crossings(policy: &DefaultPolicy) -> Vec<String> {
        denies(policy)
            .iter()
            .map(|deny| {
                let option = |name: &str| {
                    let prefix = format!(".{name}=");
                    commands(deny)
                        .into_iter()
                        .find_map(|command| Some(command.split_once(&prefix)?.1.to_string()))
                        .unwrap_or_default()
                };
                format!("{} -> {}", option("src"), option("dest"))
            })
            .collect()
    }

    #[test]
    fn whatever_leaves_the_mesh_zone_is_dropped_whichever_zone_it_goes_to() {
        // The WAN, a zone splot.yml doesn't declare, and the mesh itself.
        let policy = policy([ZoneRef::Mesh]);
        let denies = denies(&policy);
        assert_eq!(denies.len(), 1);
        assert_eq!(
            commands(&denies[0]),
            [
                "set firewall.spl_rule_deny_spl_mesh_to_any='rule'",
                "set firewall.spl_rule_deny_spl_mesh_to_any.name='[SPLOT] deny: spl_mesh to any zone'",
                "set firewall.spl_rule_deny_spl_mesh_to_any.src='spl_mesh'",
                "set firewall.spl_rule_deny_spl_mesh_to_any.dest='*'",
                "set firewall.spl_rule_deny_spl_mesh_to_any.proto='all'",
                "set firewall.spl_rule_deny_spl_mesh_to_any.target='DROP'",
            ]
        );
    }

    #[test]
    fn each_declared_zone_is_denied_into_the_mesh_and_every_other_declared_zone() {
        let policy = policy([ZoneRef::Mesh, named("iot"), named("lan")]);
        assert_eq!(
            crossings(&policy),
            [
                "'spl_mesh' -> '*'",
                "'iot' -> 'spl_mesh'",
                "'iot' -> 'lan'",
                "'lan' -> 'spl_mesh'",
                "'lan' -> 'iot'",
            ]
        );
        let lan_to_iot = denies(&policy).into_iter().last().unwrap();
        assert_eq!(
            commands(&lan_to_iot),
            [
                "set firewall.spl_rule_deny_lan_to_iot='rule'",
                "set firewall.spl_rule_deny_lan_to_iot.name='[SPLOT] deny: lan to iot'",
                "set firewall.spl_rule_deny_lan_to_iot.src='lan'",
                "set firewall.spl_rule_deny_lan_to_iot.dest='iot'",
                "set firewall.spl_rule_deny_lan_to_iot.proto='all'",
                "set firewall.spl_rule_deny_lan_to_iot.target='DROP'",
            ]
        );
    }

    #[test]
    fn without_a_mesh_zone_the_declared_zones_are_denied_into_each_other() {
        let policy = policy([named("iot"), named("lan")]);
        assert_eq!(crossings(&policy), ["'iot' -> 'lan'", "'lan' -> 'iot'"]);
        // Within one zone is the zone's own.
        assert!(denies(&self::policy([named("lan")])).is_empty());
    }
}
