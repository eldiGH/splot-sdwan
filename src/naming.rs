use crate::consts;

pub fn interface(name: &str) -> String {
    format!("{}{name}", consts::SPLOT_SECTION_PREFIX)
}

pub fn mesh_interface() -> String {
    interface(consts::MESH_INTERFACE_NAME)
}

pub fn name_prefixed(name: &str) -> String {
    format!("{}{name}", consts::SPLOT_NAME_PREFIX)
}
