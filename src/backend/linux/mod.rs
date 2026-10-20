//! Linux: the plan as the files of the programs a Linux node runs, made live
//! through systemd. Only its WireGuard so far, with wg-quick: splot doesn't
//! manage a Linux node's firewall or DHCP yet, and `apply` refuses a node that
//! asks it to.

mod apply;
mod file;
pub mod key_store;
mod wg_quick;

use log::info;

use crate::{
    backend::{self, Backend},
    plan::NodePlan,
    types::{identifier::Identifier, wg_key::WgPublicKey},
};
pub use apply::Error;
use key_store::FileKeyStore;
use wg_quick::WgQuickConfig;

/// The mesh interface: the name it has on OpenWrt too.
const INTERFACE: &str = "spl_mesh";

/// The node's config as the files splot writes, with placeholders where its
/// secrets go.
#[derive(Clone)]
pub struct Rendered {
    /// The node it's for, and the key the config has for it: the dry run and
    /// apply check this peer is that node before anything else.
    node: Identifier,
    public_key: WgPublicKey,
    /// The wg-quick file; none where splot leaves the WireGuard alone.
    wireguard: Option<WgQuickConfig>,
}

pub struct LinuxBackend {
    /// The node's key store, where splot runs its WireGuard: its key says this
    /// peer is the node, and `apply` fills its secrets into the rendered config.
    /// None where splot leaves the WireGuard alone: it keeps no key there.
    key_store: Option<FileKeyStore>,
}

impl LinuxBackend {
    pub fn new(key_store: Option<FileKeyStore>) -> Self {
        Self { key_store }
    }

    /// The wg-quick file with its secrets in, once this peer is checked to be
    /// the node `rendered` is for; none where splot leaves the WireGuard alone.
    fn confirmed<'a>(
        &self,
        rendered: &'a Rendered,
    ) -> Result<Option<(&'a WgQuickConfig, String)>, Error> {
        let store = backend::confirm_node(
            &rendered.node,
            &rendered.public_key,
            rendered.wireguard.is_some(),
            self.key_store.as_ref(),
        )?;

        // There's a store exactly where splot runs the WireGuard.
        match (&rendered.wireguard, store) {
            (Some(config), Some(store)) => Ok(Some((config, config.filled(store)?))),
            _ => Ok(None),
        }
    }
}

impl Backend for LinuxBackend {
    type Rendered = Rendered;
    type Error = Error;

    fn render(&self, plan: &NodePlan) -> Rendered {
        info!("Rendering the Linux config of node '{}'", plan.node);

        Rendered {
            node: plan.node.clone(),
            public_key: plan.public_key.clone(),
            wireguard: plan
                .wireguard
                .as_ref()
                .map(|wireguard| wg_quick::render(&plan.node, wireguard)),
        }
    }

    fn dry_run(&self, rendered: &Rendered) -> Result<(), Error> {
        match self.confirmed(rendered)? {
            Some((config, text)) => apply::print(config, &text),
            None => {
                println!("# Nothing to change.");
                Ok(())
            }
        }
    }

    fn apply(&self, rendered: &Rendered) -> Result<Vec<String>, Error> {
        match self.confirmed(rendered)? {
            Some((config, text)) => apply::run_config(config, &text),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, test_support, types::platform::Os};

    #[test]
    fn example_config_snapshot() {
        // The wg-quick file splot renders for every Linux node of the example,
        // with its secrets as placeholders: what the dry run shows.
        let network = test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/splot.example.yml"
        )));
        let backend = LinuxBackend::new(None);
        let mut rendered = 0;

        for node in network
            .nodes()
            .filter(|node| node.platform().os() == Os::Linux)
        {
            let plan = plan::plan(&network, node.name()).unwrap();
            let config = backend.render(&plan).wireguard.unwrap();

            insta::assert_snapshot!(format!("example_{}", node.name()), config.masked());
            rendered += 1;
        }
        assert!(rendered > 0);
    }

    #[test]
    fn a_node_whose_wireguard_splot_leaves_alone_has_no_file() {
        let network = test_support::checked(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: linux
      wireguard: none
      firewall: none
      dhcp: none
      dns: none
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
",
        );
        let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
        let rendered = LinuxBackend::new(None).render(&plan);

        assert!(rendered.wireguard.is_none());
        assert_eq!(rendered.public_key, plan.public_key);
    }
}
