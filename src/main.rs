use crate::{
    config::Config,
    managers::{dhcp::DhcpManager, firewall::FirewallManager, network::NetworkManager},
    pipeline::UciPipeline,
};

pub mod config;
pub mod consts;
pub mod env;
pub mod managers;
pub mod naming;
pub mod pipeline;
pub mod protocol;
pub mod splot_config;
pub mod types;
pub mod uci;
pub mod validator;
pub mod wg;

fn main() {
    env::init();
    env_logger::init();

    let private_key = splot_config::ensure_initialized();

    let config = Config::parse_file("./splot.yml").unwrap();
    let own_name = config
        .find_node_name_by_public_key(&wg::get_pubkey(&private_key))
        .unwrap_or_else(|| {
            eprintln!("Error: this router's public key was not found in splot config file.");
            eprintln!("Add this node to the config and try again.");
            std::process::exit(1);
        });

    UciPipeline::new()
        .register(NetworkManager)
        .register(FirewallManager)
        .register(DhcpManager)
        .run(&config, own_name);
}
