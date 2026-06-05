use std::{
    fs, io,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

const CONFIG_DIRECTORY: &str = "firmapache";
const LEGACY_CONFIG_DIRECTORY: &str = "mini-firmador";
const CONFIG_FILE: &str = "config.toml";
const LEGACY_DEFAULT_SERVER_PORT: u16 = 4856;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default = "default_server_host")]
    pub host: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    #[serde(default = "default_server_https")]
    pub https: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            https: default_server_https(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Pkcs11Config {
    #[serde(default = "default_pkcs11_library_path")]
    pub library_path: Option<String>,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            library_path: default_pkcs11_library_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningConfig {
    pub default_identity_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DevelopmentConfig {
    pub enabled: bool,
    pub auto_sign: bool,
    pub default_identity_id: String,
    #[serde(default = "default_development_pin_env")]
    pub pin_env: String,
    pub fallback_to_modal: bool,
    pub pkcs12_tokens: Vec<Pkcs12TokenConfig>,
}

impl Default for DevelopmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_sign: false,
            default_identity_id: String::new(),
            pin_env: default_development_pin_env(),
            fallback_to_modal: true,
            pkcs12_tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Pkcs12TokenConfig {
    pub id: String,
    pub label: String,
    pub path: String,
    pub password_env: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub pkcs11: Pkcs11Config,
    pub cors: CorsConfig,
    pub signing: SigningConfig,
    pub development: DevelopmentConfig,
}

fn default_server_host() -> String {
    "127.0.0.1".to_owned()
}

fn default_server_port() -> u16 {
    4637
}

fn default_server_https() -> bool {
    true
}

fn default_pkcs11_library_path() -> Option<String> {
    Some("/usr/lib/libcastle.so.1.0.0".to_owned())
}

fn default_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost:3000".to_owned(),
        "http://127.0.0.1:3000".to_owned(),
    ]
}

fn default_development_pin_env() -> String {
    "FIRMAPACHE_DEV_PIN".to_owned()
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::config_path()?;
        info!(path = %path.display(), "configuration path selected");

        if !path.exists() {
            if let Some(legacy_path) = Self::legacy_config_path()? {
                let contents =
                    fs::read_to_string(&legacy_path).map_err(|source| ConfigError::Read {
                        path: legacy_path.clone(),
                        source,
                    })?;
                let mut config: Self =
                    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
                        path: legacy_path.clone(),
                        source,
                    })?;
                if config.development.pin_env == "MINI_FIRMADOR_DEV_PIN" {
                    config.development.pin_env = default_development_pin_env();
                }
                config.validate()?;
                config.save_to(&path)?;
                info!(
                    old_path = %legacy_path.display(),
                    new_path = %path.display(),
                    "legacy configuration migrated to FirMapache path"
                );
                return Ok(config);
            }
            let config = Self::default();
            config.save_to(&path)?;
            info!(path = %path.display(), "default configuration created");
            return Ok(config);
        }

        let contents = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let raw: toml::Value = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        let uses_legacy_server_defaults = raw
            .get("server")
            .and_then(toml::Value::as_table)
            .is_some_and(|server| !server.contains_key("https"));
        let mut config: Self = raw.try_into().map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;

        if uses_legacy_server_defaults && config.server.port == LEGACY_DEFAULT_SERVER_PORT {
            config.server.port = default_server_port();
            config.save_to(&path)?;
            info!(
                path = %path.display(),
                old_port = LEGACY_DEFAULT_SERVER_PORT,
                new_port = config.server.port,
                "legacy server configuration migrated to HTTPS defaults"
            );
        }

        config.validate()?;
        info!(path = %path.display(), "configuration loaded");

        Ok(config)
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::config_path()?)
    }

    pub fn config_path() -> Result<PathBuf, ConfigError> {
        Ok(Self::config_directory()?.join(CONFIG_FILE))
    }

    pub fn config_directory() -> Result<PathBuf, ConfigError> {
        dirs::config_dir()
            .map(|directory| directory.join(CONFIG_DIRECTORY))
            .ok_or(ConfigError::ConfigDirectoryUnavailable)
    }

    fn legacy_config_path() -> Result<Option<PathBuf>, ConfigError> {
        let Some(directory) = dirs::config_dir() else {
            return Err(ConfigError::ConfigDirectoryUnavailable);
        };
        let path = directory.join(LEGACY_CONFIG_DIRECTORY).join(CONFIG_FILE);
        Ok(path.exists().then_some(path))
    }

    pub fn bind_address(&self) -> Result<SocketAddr, ConfigError> {
        let address = format!("{}:{}", self.server.host, self.server.port);
        address
            .to_socket_addrs()
            .map_err(|_| ConfigError::Invalid(format!("invalid server address: {address}")))?
            .next()
            .ok_or_else(|| ConfigError::Invalid(format!("invalid server address: {address}")))
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
            if let Some(https) = server.https {
                config.server.https = https;
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
        if let Some(signing) = update.signing {
            if let Some(default_identity_id) = signing.default_identity_id {
                config.signing.default_identity_id = default_identity_id;
            }
        }
        if let Some(development) = update.development {
            if let Some(enabled) = development.enabled {
                config.development.enabled = enabled;
            }
            if let Some(auto_sign) = development.auto_sign {
                config.development.auto_sign = auto_sign;
            }
            if let Some(default_identity_id) = development.default_identity_id {
                config.development.default_identity_id = default_identity_id;
            }
            if let Some(pin_env) = development.pin_env {
                config.development.pin_env = pin_env;
            }
            if let Some(fallback_to_modal) = development.fallback_to_modal {
                config.development.fallback_to_modal = fallback_to_modal;
            }
            if let Some(pkcs12_tokens) = development.pkcs12_tokens {
                config.development.pkcs12_tokens = pkcs12_tokens;
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
        if self.server.host.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "server.host cannot be empty".to_owned(),
            ));
        }
        if !(1024..=65535).contains(&self.server.port) {
            return Err(ConfigError::Invalid(
                "server.port must be between 1024 and 65535".to_owned(),
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
        if self.development.pin_env.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "development.pin_env cannot be empty".to_owned(),
            ));
        }
        let mut token_ids = std::collections::HashSet::new();
        for token in &self.development.pkcs12_tokens {
            if token.id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "development.pkcs12_tokens.id cannot be empty".to_owned(),
                ));
            }
            if !token_ids.insert(token.id.trim()) {
                return Err(ConfigError::Invalid(format!(
                    "development.pkcs12_tokens id must be unique: {}",
                    token.id
                )));
            }
            if token.path.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "development.pkcs12_tokens path cannot be empty for {}",
                    token.id
                )));
            }
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
    pub signing: Option<SigningConfigUpdate>,
    pub development: Option<DevelopmentConfigUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfigUpdate {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub https: Option<bool>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningConfigUpdate {
    pub default_identity_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentConfigUpdate {
    pub enabled: Option<bool>,
    pub auto_sign: Option<bool>,
    pub default_identity_id: Option<String>,
    pub pin_env: Option<String>,
    pub fallback_to_modal: Option<bool>,
    pub pkcs12_tokens: Option<Vec<Pkcs12TokenConfig>>,
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
