use crate::consts;

pub use splot_core::uci::naming::{UciSectionName, mesh_interface};

pub fn name_prefixed(name: &str) -> String {
    format!("{}{name}", consts::SPLOT_NAME_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_prefixed_prepends_bracket_label() {
        assert_eq!(name_prefixed("foo"), "[SPLOT] foo");
    }
}
