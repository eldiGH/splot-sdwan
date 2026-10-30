//! Backends: how a node's plan becomes config on the platform it runs. splot
//! renders it; the agent on the node applies it (`splot-agent`).

pub mod linux;
pub mod openwrt;

use splot_core::{os::Os, protocol::Rendered};

use crate::{model::platform::Platform, plan::NodePlan};

/// The plan as the config of `platform`, the one the node runs: what the agent
/// makes the node hold. Pure, so it can be tested without the node.
pub fn render(plan: &NodePlan, platform: &Platform) -> Rendered {
    match platform.os() {
        Os::OpenWrt => Rendered::OpenWrt(openwrt::render(plan)),
        Os::Linux => Rendered::Linux(linux::render(plan, platform)),
    }
}
