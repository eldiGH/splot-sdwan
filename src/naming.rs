use const_format::concatcp;

use crate::consts;

pub fn mesh_interface_name() -> &'static str {
    concatcp!(consts::SPLOT_PREFIX, "mesh")
}

pub fn vpn_interface_name(interface_key_name: &str) -> String {
    format!("{}{}", consts::SPLOT_PREFIX, interface_key_name)
}
