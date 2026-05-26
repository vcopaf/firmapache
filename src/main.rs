mod config;
mod core;
mod error;
mod models;
mod server;
mod utils;

use anyhow::{Context, Result};
use config::AppConfig;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AppConfig::load().context("could not load service configuration")?;
    let address = config
        .bind_address()
        .context("could not resolve service bind address")?;
    let https = config.server.https;
    info!(origins = ?config.cors.allowed_origins, "CORS allowed origins configured");
    let app = server::router(config)?;

    if https {
        let tls_config = server::tls::load_or_generate_config().await?;
        info!(%address, "mini-firmador HTTPS service started");

        axum_server::bind_rustls(address, tls_config)
            .serve(app.into_make_service())
            .await
            .context("local HTTPS server failed")
    } else {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("could not bind service to {address}"))?;
        info!(%address, "mini-firmador HTTP service started");

        axum::serve(listener, app)
            .await
            .context("local HTTP server failed")
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
