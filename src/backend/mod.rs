//! Backends: how a node's plan becomes config on the platform it runs.

pub mod key_store;
pub mod linux;
pub mod openwrt;

use std::path::Path;

use crate::{plan::NodePlan, types::platform::Os};

/// The file every OpenWrt has, saying which release it is.
const OPENWRT_RELEASE: &str = "/etc/openwrt_release";

/// The OS this peer runs, as far as splot can tell: OpenWrt by its release
/// file, any other Linux as Linux. None for anything else.
pub fn detect_os() -> Option<Os> {
    if Path::new(OPENWRT_RELEASE).exists() {
        Some(Os::OpenWrt)
    } else if cfg!(target_os = "linux") {
        Some(Os::Linux)
    } else {
        None
    }
}

/// A platform splot configures a node through.
pub trait Backend {
    /// The plan as this platform's config.
    type Rendered;
    type Error;

    /// The plan as this platform's config: what `apply` writes. Pure, so it can
    /// be tested without the node.
    fn render(&self, plan: &NodePlan) -> Self::Rendered;

    /// Shows what `apply` would change on the node, changing nothing.
    fn dry_run(&self, rendered: &Self::Rendered) -> Result<(), Self::Error>;

    /// Makes the rendered config live on the node. Returns what changed.
    fn apply(&self, rendered: &Self::Rendered) -> Result<Vec<String>, Self::Error>;
}
