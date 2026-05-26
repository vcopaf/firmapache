pub mod handlers;
mod routes;
pub mod tls;

use std::sync::{Arc, RwLock};

use crate::{
    config::{AppConfig, ConfigError},
    core::signing::session_manager::SigningSessionManager,
    error::AppError,
};

pub use routes::router;

#[derive(Clone)]
pub struct AppState {
    config: Arc<RwLock<AppConfig>>,
    signing_sessions: SigningSessionManager,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            signing_sessions: SigningSessionManager::new(),
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

        Ok(())
    }

    pub fn signing_sessions(&self) -> &SigningSessionManager {
        &self.signing_sessions
    }
}
