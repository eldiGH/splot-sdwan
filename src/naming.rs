use crate::consts;

pub fn interface(device_name: &str) -> String {
    format!("{}{device_name}", consts::SPLOT_SECTION_PREFIX)
}

pub fn mesh_interface() -> String {
    interface("mesh")
}

pub fn name_prefixed(name: &str) -> String {
    format!("{}{name}", consts::SPLOT_NAME_PREFIX)
}
