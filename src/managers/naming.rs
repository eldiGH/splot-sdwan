use std::fmt::{self, Display};

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
    pub fn new<P: Display>(parts: impl IntoIterator<Item = P>) -> Self {
        let joined = parts
            .into_iter()
            .map(|part| part.to_string())
            .collect::<Vec<_>>()
            .join("_");

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

/// The name of a splot-managed network interface, which is also its section name.
/// Zone `network` lists and peer section types refer to it.
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
    fn hyphens_become_underscores() {
        // uci rejects '-' in section names ("uci: Invalid argument").
        assert_eq!(interface("guest-wifi").as_str(), "spl_guest_wifi");
        assert_eq!(
            UciSectionName::new(["rule", "my-printer", "print"]).as_str(),
            "spl_rule_my_printer_print"
        );
    }

    #[test]
    fn name_prefixed_prepends_bracket_label() {
        assert_eq!(name_prefixed("foo"), "[SPLOT] foo");
    }
}
