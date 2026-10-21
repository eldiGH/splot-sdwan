//! splot's agent: everything splot does on a node. splot validates the config,
//! plans each node and renders what it should hold; the agent, on the node,
//! checks it's the node the config is for, fills the secrets in from the
//! node's key store, and makes the node hold it. No secret leaves the node.

mod env;
pub mod key_store;
pub mod linux;
pub mod node;
pub mod openwrt;
pub mod process;
mod secret;
#[cfg(test)]
mod test_support;
pub mod wg;

use splot_core::{
    os::Os,
    protocol::{Failure, Rendered, Reply, Request},
};

/// Does what `request` asks, on this peer.
pub fn handle(request: Request) -> Reply {
    let result = match request {
        Request::Apply { rendered, dry_run } => apply(&rendered, dry_run),
    };

    result.unwrap_or_else(|error| Reply::Failed(Failure::of(error.as_ref())))
}

/// Makes this peer hold `rendered`, or (`dry_run`) says what that would change,
/// once it's checked this peer runs the OS `rendered` is for.
fn apply(
    rendered: &Rendered,
    dry_run: bool,
) -> Result<Reply, Box<dyn std::error::Error + Send + Sync>> {
    let (node, os) = match rendered {
        Rendered::OpenWrt(rendered) => (&rendered.node, Os::OpenWrt),
        Rendered::Linux(rendered) => (&rendered.node, Os::Linux),
    };
    node::check_os(node, os)?;

    Ok(match (rendered, dry_run) {
        (Rendered::OpenWrt(rendered), true) => Reply::DryRun(openwrt::dry_run(rendered)?),
        (Rendered::OpenWrt(rendered), false) => Reply::Applied(openwrt::apply(rendered)?),
        (Rendered::Linux(rendered), true) => Reply::DryRun(linux::dry_run(rendered)?),
        (Rendered::Linux(rendered), false) => Reply::Applied(linux::apply(rendered)?),
    })
}

#[cfg(test)]
mod tests {
    use splot_core::protocol::{linux, openwrt};

    use super::*;

    #[test]
    fn a_config_for_another_os_than_this_peers_is_refused_before_anything_else() {
        // Where the tests run, the OS splot detects; the config says the other.
        let Some(found) = node::detect_os() else {
            return;
        };
        let (node, public_key) = (
            "Home".parse().unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
        );
        let rendered = match found {
            Os::Linux => Rendered::OpenWrt(openwrt::Rendered {
                node,
                public_key,
                wireguard: true,
                files: Vec::new(),
                secrets: Vec::new(),
            }),
            Os::OpenWrt => Rendered::Linux(linux::Rendered {
                node,
                public_key,
                wireguard: None,
            }),
        };
        let os = match found {
            Os::Linux => Os::OpenWrt,
            Os::OpenWrt => Os::Linux,
        };

        for dry_run in [true, false] {
            let reply = handle(Request::Apply {
                rendered: rendered.clone(),
                dry_run,
            });
            assert_eq!(
                reply,
                Reply::Failed(Failure(vec![format!(
                    "this peer runs {found}, but the config says Home runs {os}"
                )]))
            );
        }
    }
}
