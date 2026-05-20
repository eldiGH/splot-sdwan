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
