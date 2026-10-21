fn get_env_variable(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Where uci keeps its files, for local development (`uci -c`); none: uci's own.
pub fn uci_config_dir() -> Option<String> {
    get_env_variable("SPLOT_UCI_CONFIG_DIR")
}
