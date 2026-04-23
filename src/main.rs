use crate::{config::Config, managers::network::NetworkManager, pipeline::UciPipeline};

pub mod config;
pub mod env;
pub mod managers;
pub mod pipeline;
pub mod protocols;
pub mod types;
pub mod uci;

fn main() {
    env::init();

    let config = Config::parse_file("./splot.json").unwrap();

    UciPipeline::new()
        .add(Box::new(NetworkManager))
        .run(&config)
        .unwrap();
}
