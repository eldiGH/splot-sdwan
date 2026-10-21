pub fn init() {
    #[cfg(debug_assertions)]
    dotenvy::dotenv().ok();
}
