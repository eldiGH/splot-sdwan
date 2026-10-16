//! Backends: how a node's plan becomes config on the platform it runs.

pub mod openwrt;

use crate::plan::NodePlan;

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
