pub mod handlers;
mod routes;
pub mod tls;

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tracing::info;

use crate::{
    config::{AppConfig, ConfigError},
    core::{cache::TokenCertificateCache, signing::session_manager::SigningSessionManager},
    error::AppError,
};

pub use routes::router;

#[derive(Clone)]
pub struct AppState {
    config: Arc<RwLock<AppConfig>>,
    signing_sessions: SigningSessionManager,
    token_certificate_cache: TokenCertificateCache,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            signing_sessions: SigningSessionManager::new(),
            token_certificate_cache: TokenCertificateCache::new(),
        }
    }

    pub fn config(&self) -> Result<AppConfig, AppError> {
        self.config
            .read()
            .map(|config| config.clone())
            .map_err(|_| ConfigError::StateLock.into())
    }

    pub fn replace_config(&self, config: AppConfig) -> Result<(), AppError> {
        let mut active_config = self.config.write().map_err(|_| ConfigError::StateLock)?;
        *active_config = config;
        let _ = self.token_certificate_cache.invalidate();

        Ok(())
    }

    pub fn signing_sessions(&self) -> &SigningSessionManager {
        &self.signing_sessions
    }

    pub fn token_certificate_cache(&self) -> &TokenCertificateCache {
        &self.token_certificate_cache
    }
}

pub async fn serve(state: AppState) -> Result<()> {
    let config = state
        .config()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("could not read service configuration")?;
    let address = config
        .bind_address()
        .context("could not resolve service bind address")?;
    let https = config.server.https;
    info!(origins = ?config.cors.allowed_origins, "CORS allowed origins configured");
    let app = router(state)?;

    if https {
        let tls_config = tls::load_or_generate_config().await?;
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
