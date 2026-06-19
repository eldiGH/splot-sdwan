use crate::consts;

pub fn interface(name: impl AsRef<str>) -> String {
    format!("{}{}", consts::SPLOT_SECTION_PREFIX, name.as_ref())
}

pub fn mesh_interface() -> String {
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
        assert_eq!(interface("x"), "spl_x");
        assert_eq!(interface("my_rule"), "spl_my_rule");
    }

    #[test]
    fn mesh_interface_is_spl_splot_mesh() {
        assert_eq!(mesh_interface(), "spl_splot_mesh");
    }

    #[test]
    fn name_prefixed_prepends_bracket_label() {
        assert_eq!(name_prefixed("foo"), "[SPLOT] foo");
    }
}
