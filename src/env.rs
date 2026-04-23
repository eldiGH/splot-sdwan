pub fn init() {
    #[cfg(debug_assertions)]
    dotenvy::dotenv().ok();
}

fn get_env_variable(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

pub fn uci_config_dir() -> Option<String> {
    get_env_variable("SPLOT_UCI_CONFIG_DIR")
}
