/// What starts the name of every uci section splot writes, and no identifier
/// in the config.
pub const SPLOT_SECTION_PREFIX: &str = "spl_";
pub const MESH_INTERFACE_NAME: &str = "mesh";
/// The mesh interface's device on the node, on every platform: netifd names it
/// after its uci section, and wg-quick after its file.
pub const MESH_DEVICE: &str = "spl_mesh";
/// splot's own nftables table on a Linux node, `inet splot`: its family and
/// its name. splot renders it, the agent loads it, and nothing of splot's
/// touches another.
pub const NFT_FAMILY: &str = "inet";
pub const NFT_TABLE: &str = "splot";
/// splot's dnsmasq config file on a Linux node, which the operator's dnsmasq
/// reads (`conf-file=` it in its config): splot renders it, the agent writes
/// it and has dnsmasq read it.
pub const DNSMASQ_PATH: &str = "/etc/splot/dnsmasq.conf";
