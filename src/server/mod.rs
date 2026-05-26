pub mod handlers;
mod routes;
pub mod tls;

use std::sync::{Arc, RwLock};

use crate::{
    config::{AppConfig, ConfigError},
    error::AppError,
};

pub use routes::router;

#[derive(Clone)]
pub struct AppState {
    config: Arc<RwLock<AppConfig>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
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
}
