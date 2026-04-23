use std::{fs, path::PathBuf};

use crate::{
    env,
    uci::{UciBatchCommand, UciExecutor},
    wg,
};

fn get_config_dir() -> PathBuf {
    PathBuf::from(env::uci_config_dir().unwrap_or("/etc/config".to_owned()))
}

fn add_splot_section() -> String {
    let private_key = wg::generate_private_key();

    UciExecutor::batch(vec![
        UciBatchCommand::set("splot.config", "splot"),
        UciBatchCommand::set("splot.config.private_key", &private_key),
        UciBatchCommand::commit("splot"),
    ]);

    private_key
}

pub fn ensure_initialized() -> String {
    let splot_file_path = get_config_dir().join("splot");

    if !splot_file_path.exists() {
        fs::File::create(&splot_file_path).unwrap();
        return add_splot_section();
    }

    UciExecutor::get("splot.config.private_key").unwrap_or_else(add_splot_section)
}
