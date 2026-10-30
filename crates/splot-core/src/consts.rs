/// What starts the name of every uci section splot writes, and no identifier
/// in the config.
pub const SPLOT_SECTION_PREFIX: &str = "spl_";
pub const MESH_INTERFACE_NAME: &str = "mesh";
/// The mesh interface's device on the node, on every platform: netifd names it
/// after its uci section, and wg-quick after its file.
pub const MESH_DEVICE: &str = "spl_mesh";
