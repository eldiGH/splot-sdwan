use std::{
    fmt::{self, Display},
    iter,
};

use crate::{consts, uci};

/// The name of a splot-owned uci section: `spl_` followed by its parts joined with
/// `_`, mapped to uci's character set (`uci::name`).
///
/// Every generated section — and every reference to one (a zone's `network` list,
/// a peer's `wireguard_<interface>` type) — is built here, so the mapping can't
/// diverge between a section and the places that point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciSectionName(String);

impl UciSectionName {
    /// An untagged name, for sections other config refers to by name: interfaces,
    /// zones, DHCP hosts.
    pub fn new<P: Display>(parts: impl IntoIterator<Item = P>) -> Self {
        Self::join(parts.into_iter().map(|part| part.to_string()))
    }

    /// A name whose kind tag comes right after `spl_`, for sections that share a
    /// uci file with sections of another kind.
    pub fn tagged<P: Display>(kind: SectionKind, parts: impl IntoIterator<Item = P>) -> Self {
        let parts = parts.into_iter().map(|part| part.to_string());

        Self::join(iter::once(kind.tag().to_owned()).chain(parts))
    }

    fn join(parts: impl Iterator<Item = String>) -> Self {
        let joined = parts.collect::<Vec<_>>().join("_");

        Self(format!(
            "{}{}",
            consts::SPLOT_SECTION_PREFIX,
            uci::name(&joined)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for UciSectionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Kinds of sections that share a uci file with sections of another kind. The tag
/// keeps them apart, so that, e.g., a peer can never be named like an interface,
/// nor an ingress rule like the egress rule of the same service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Peer,
    RuleIn,
    RuleOut,
    Dnat,
}

impl SectionKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::RuleIn => "in",
            Self::RuleOut => "out",
            Self::Dnat => "dnat",
        }
    }
}

/// A splot-managed network interface (also the name of its firewall zone section).
pub fn interface(name: impl Display) -> UciSectionName {
    UciSectionName::new([name])
}

pub fn mesh_interface() -> UciSectionName {
    interface(consts::MESH_INTERFACE_NAME)
}

pub fn name_prefixed(name: &str) -> String {
    format!("{}{name}", consts::SPLOT_NAME_PREFIX)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn interface_prepends_spl_prefix() {
        assert_eq!(interface("x").as_str(), "spl_x");
        assert_eq!(interface("my_rule").as_str(), "spl_my_rule");
    }

    #[test]
    fn mesh_interface_is_spl_mesh() {
        assert_eq!(mesh_interface().as_str(), "spl_mesh");
    }

    #[test]
    fn section_name_joins_parts_with_underscore() {
        let name = UciSectionName::new(["mesh", "Phone"]);
        assert_eq!(name.as_str(), "spl_mesh_Phone");
        assert_eq!(name.to_string(), "spl_mesh_Phone");
    }

    #[test]
    fn tagged_puts_the_kind_right_after_the_prefix() {
        assert_eq!(
            UciSectionName::tagged(SectionKind::Peer, ["mesh", "Phone"]).as_str(),
            "spl_peer_mesh_Phone"
        );
        assert_eq!(
            UciSectionName::tagged(SectionKind::RuleIn, ["Home", "ssh"]).as_str(),
            "spl_in_Home_ssh"
        );
        assert_eq!(
            UciSectionName::tagged(SectionKind::RuleOut, ["Home", "ssh"]).as_str(),
            "spl_out_Home_ssh"
        );
        assert_eq!(
            UciSectionName::tagged(SectionKind::Dnat, ["Home", "ssh"]).as_str(),
            "spl_dnat_Home_ssh"
        );
    }

    #[test]
    fn kind_tags_are_distinct() {
        // Two kinds sharing a tag would let their sections collide again.
        let kinds = [
            SectionKind::Peer,
            SectionKind::RuleIn,
            SectionKind::RuleOut,
            SectionKind::Dnat,
        ];
        let tags: HashSet<&str> = kinds.iter().map(|kind| kind.tag()).collect();
        assert_eq!(tags.len(), kinds.len());
    }

    #[test]
    fn hyphens_become_underscores() {
        // uci rejects '-' in section names ("uci: Invalid argument").
        assert_eq!(interface("guest-wifi").as_str(), "spl_guest_wifi");
        assert_eq!(
            UciSectionName::tagged(SectionKind::RuleIn, ["my-printer", "print"]).as_str(),
            "spl_in_my_printer_print"
        );
    }

    #[test]
    fn name_prefixed_prepends_bracket_label() {
        assert_eq!(name_prefixed("foo"), "[SPLOT] foo");
    }
}
