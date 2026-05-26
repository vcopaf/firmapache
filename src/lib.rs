pub mod config;
pub mod core;
pub mod error;
pub mod models;
pub mod server;
pub mod utils;

use tracing_subscriber::EnvFilter;

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}
