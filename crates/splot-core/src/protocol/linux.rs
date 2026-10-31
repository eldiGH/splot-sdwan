//! The config of a Linux node: its WireGuard as a wg-quick file, its firewall
//! as an nft file, its DHCP as a dnsmasq file.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{identifier::Identifier, secret::Secret, wg_key::WgPublicKey};

/// The node's config as the files splot writes, with placeholders where its
/// secrets go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rendered {
    /// The node it's for, and the key the config has for it: the agent checks
    /// it runs on that node before anything else.
    pub node: Identifier,
    pub public_key: WgPublicKey,
    /// The wg-quick file; none where splot leaves the WireGuard alone.
    pub wireguard: Option<WgQuickConfig>,
    /// The nft file of splot's own table; none where splot leaves the firewall
    /// alone. It holds no secret.
    pub firewall: Option<String>,
    /// splot's dnsmasq file; none where splot leaves the DHCP alone. It holds
    /// no secret.
    pub dhcp: Option<String>,
}

/// A line of the file: as it is, or a key whose value is a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Line {
    Text(String),
    Secret { key: String, secret: Secret },
}

/// The file, and what wg-quick sets up from it besides WireGuard itself when it
/// brings the interface up: its address and its routes. `wg syncconf` changes
/// neither, so apply restarts the interface when what's live differs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgQuickConfig {
    pub lines: Vec<Line>,
    /// The address, as `ip` shows it: `10.100.0.1/16`.
    pub address: String,
    /// The routes, each as `ip` shows a network: `192.168.2.0/24`.
    pub routes: BTreeSet<String>,
}

impl WgQuickConfig {
    /// The file with each secret's placeholder: what the dry run shows.
    pub fn masked(&self) -> String {
        self.text(self.secrets().map(Secret::placeholder))
    }

    pub fn secrets(&self) -> impl Iterator<Item = &Secret> {
        self.lines.iter().filter_map(|line| match line {
            Line::Secret { secret, .. } => Some(secret),
            Line::Text(_) => None,
        })
    }

    /// The lines with `values` for the secrets, in order.
    pub fn text<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> String {
        let mut values = values.into_iter();
        let mut text = String::new();

        for line in &self.lines {
            match line {
                Line::Text(line) => text.push_str(line),
                Line::Secret { key, .. } => {
                    let value = values.next().expect("a value for every secret");
                    text.push_str(&format!("{key} = {value}"));
                }
            }
            text.push('\n');
        }

        text
    }
}
