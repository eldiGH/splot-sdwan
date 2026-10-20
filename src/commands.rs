//! What each command does, once the config is loaded and checked.

use anyhow::{Context, bail};

use crate::{
    backend::{
        Backend,
        openwrt::{OpenWrtBackend, splot_config::SplotConfig},
    },
    model::Network,
    plan::{self, NodePlan},
    types::wg_key::WgPresharedKey,
    wg,
};

/// `apply`: makes this router's config what the plan says, or shows what that
/// would change (`dry_run`).
pub fn apply(network: &Network, dry_run: bool) -> anyhow::Result<()> {
    let splot_config = SplotConfig::load()?;
    let plan = own_plan(network, &splot_config)?;

    let backend = OpenWrtBackend::new(splot_config);
    let rendered = backend.render(&plan);

    if dry_run {
        backend.dry_run(&rendered)?;
    } else {
        let changed = backend.apply(&rendered)?;

        if changed.is_empty() {
            println!("Nothing changed.");
        } else {
            println!("Applied and reloaded: {}", changed.join(", "));
        }
    }

    Ok(())
}

/// `psk set`: stores the preshared key of this router's pair with `peer`, read
/// from stdin.
pub fn psk_set(network: &Network, peer: &str) -> anyhow::Result<()> {
    let splot_config = SplotConfig::load()?;
    let plan = own_plan(network, &splot_config)?;

    let Some(peer) = plan.wireguard.peer(peer) else {
        let peers: Vec<String> = plan
            .wireguard
            .peers
            .iter()
            .map(|peer| peer.host.to_string())
            .collect();
        bail!(
            "'{peer}' isn't a peer of {}; its peers are {}",
            plan.node,
            peers.join(", ")
        );
    };
    if !peer.psk {
        bail!(
            "{}'s pair with {} uses no preshared key: one of them sets `psk: false`",
            plan.node,
            peer.host
        );
    }

    let mut key = String::new();
    std::io::stdin()
        .read_line(&mut key)
        .context("failed to read the preshared key from stdin")?;
    let key: WgPresharedKey = key
        .trim()
        .parse()
        .context("that's not a preshared key (as `wg genpsk` prints one)")?;
    SplotConfig::store_psk(&peer.host, &key)?;

    println!(
        "Stored the preshared key of {}'s pair with {}.",
        plan.node, peer.host
    );

    Ok(())
}

/// This router's plan: the node whose public key follows from the local private
/// key.
fn own_plan(network: &Network, splot_config: &SplotConfig) -> anyhow::Result<NodePlan> {
    let own_public_key = wg::get_pubkey(splot_config.mesh_key())
        .context("failed to derive this router's public key")?;

    network
        .find_node_by_public_key(own_public_key.as_str())
        .and_then(|node| plan::plan(network, node.name()))
        .context(
            "this router's public key was not found in the splot config - add this node and try again",
        )
}
