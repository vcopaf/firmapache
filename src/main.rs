mod api;
mod config;
mod crypto;
mod error;
mod models;
mod pkcs11;
mod utils;

use anyhow::{Context, Result};
use config::AppConfig;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AppConfig::default();
    let address = config.bind_address();
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind service to {address}"))?;

    info!(origins = ?config.allowed_origins, "CORS allowed origins configured");
    info!(%address, "mini-firmador service started");

    axum::serve(listener, api::router(&config)?)
        .await
        .context("local HTTP server failed")
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
