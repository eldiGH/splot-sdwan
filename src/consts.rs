pub const SPLOT_SECTION_PREFIX: &str = "spl_";
pub const SPLOT_NAME_PREFIX: &str = "[SPLOT] ";
pub const MESH_INTERFACE_NAME: &str = "mesh";
/// `{Node}.hub` refers to the node's hub network.
pub const HUB_NAME: &str = "hub";
/// Local names (zones, devices, hub clients) that splot gives a meaning of its
/// own on every node.
pub const RESERVED_LOCAL_NAMES: [&str; 1] = [HUB_NAME];
pub const CURRENT_NODE_IDENTIFIER: &str = "$node";
