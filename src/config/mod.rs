use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

const CONFIG_DIRECTORY: &str = "mini-firmador";
const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 4856,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Pkcs11Config {
    pub library_path: Option<String>,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            library_path: Some("/usr/lib/libcastle.so.1.0.0".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec![
                "http://localhost:3000".to_owned(),
                "http://127.0.0.1:3000".to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub pkcs11: Pkcs11Config,
    pub cors: CorsConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::config_path()?;
        info!(path = %path.display(), "configuration path selected");

        if !path.exists() {
            let config = Self::default();
            config.save_to(&path)?;
            info!(path = %path.display(), "default configuration created");
            return Ok(config);
        }

        let contents = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let config: Self = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        config.validate()?;
        info!(path = %path.display(), "configuration loaded");

        Ok(config)
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::config_path()?)
    }

    pub fn config_path() -> Result<PathBuf, ConfigError> {
        dirs::config_dir()
            .map(|directory| directory.join(CONFIG_DIRECTORY).join(CONFIG_FILE))
            .ok_or(ConfigError::ConfigDirectoryUnavailable)
    }

    pub fn bind_address(&self) -> Result<SocketAddr, ConfigError> {
        let address = format!("{}:{}", self.server.host, self.server.port);
        address
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("invalid server address: {address}")))
    }

    pub fn apply_update(&self, update: AppConfigUpdate) -> Result<Self, ConfigError> {
        let mut config = self.clone();

        if let Some(server) = update.server {
            if let Some(host) = server.host {
                config.server.host = host;
            }
            if let Some(port) = server.port {
                config.server.port = port;
            }
        }
        if let Some(pkcs11) = update.pkcs11 {
            if let Some(library_path) = pkcs11.library_path {
                config.pkcs11.library_path = Some(library_path);
            }
        }
        if let Some(cors) = update.cors {
            if let Some(allowed_origins) = cors.allowed_origins {
                config.cors.allowed_origins = allowed_origins;
            }
        }

        config.validate()?;
        Ok(config)
    }

    fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let directory = path
            .parent()
            .ok_or(ConfigError::ConfigDirectoryUnavailable)?;
        fs::create_dir_all(directory).map_err(|source| ConfigError::CreateDirectory {
            path: directory.to_path_buf(),
            source,
        })?;
        let contents = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        fs::write(path, contents).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        info!(path = %path.display(), "configuration saved");

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::Invalid(
                "server.port must be greater than zero".to_owned(),
            ));
        }
        self.bind_address()?;
        if self.cors.allowed_origins.iter().any(|origin| {
            origin.is_empty()
                || !origin
                    .bytes()
                    .all(|character| matches!(character, 0x20..=0x7e))
        }) {
            return Err(ConfigError::Invalid(
                "cors.allowed_origins contains an invalid HTTP origin value".to_owned(),
            ));
        }
        if self
            .pkcs11
            .library_path
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err(ConfigError::Invalid(
                "pkcs11.library_path cannot be empty".to_owned(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfigUpdate {
    pub server: Option<ServerConfigUpdate>,
    pub pkcs11: Option<Pkcs11ConfigUpdate>,
    pub cors: Option<CorsConfigUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfigUpdate {
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11ConfigUpdate {
    pub library_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfigUpdate {
    pub allowed_origins: Option<Vec<String>>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not determine user configuration directory")]
    ConfigDirectoryUnavailable,
    #[error("could not create configuration directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not parse configuration file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("could not serialize configuration: {0}")]
    Serialize(#[source] toml::ser::Error),
    #[error("could not write configuration file {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("configuration state lock is unavailable")]
    StateLock,
}
