use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{
    config::AppConfig,
    core::identity::{SigningIdentity, build_signing_identities},
    core::pkcs11::provider::{self, ProviderError},
    models::pkcs11::{CertificateInfo, TokenInfo},
};

const CACHE_TTL_SECONDS: i64 = 60;
const CACHE_DIRECTORY: &str = "cache";
const TOKEN_CERTIFICATE_CACHE_FILE: &str = "token-certificates.json";

#[derive(Clone)]
pub struct TokenCertificateCache {
    inner: Arc<RwLock<TokenCertificateCacheState>>,
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TokenCertificateCacheState {
    pub tokens: Vec<TokenInfo>,
    pub certificates: Vec<CertificateInfo>,
    pub loaded_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub certificates_loaded_at: Option<DateTime<Utc>>,
    pub pkcs11_library_path: Option<String>,
    pub token_fingerprint: Option<String>,
    pub last_event: Option<String>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub watcher_backend: Option<String>,
    pub watcher_active: bool,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl TokenCertificateCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TokenCertificateCacheState::default())),
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn snapshot(&self) -> Result<TokenCertificateCacheState, CacheError> {
        if let Ok(state) = self.inner.read()
            && state.loaded_at.is_some()
        {
            return Ok(state.clone());
        }
        if let Some(state) = read_persisted_cache()? {
            *self.inner.write().map_err(|_| CacheError::StateLock)? = state.clone();
            return Ok(state);
        }
        self.inner
            .read()
            .map(|state| state.clone())
            .map_err(|_| CacheError::StateLock)
    }

    pub fn get_cached_tokens(&self) -> Result<Vec<TokenInfo>, CacheError> {
        Ok(self.snapshot()?.tokens)
    }

    pub fn get_cached_certificates(&self) -> Result<Vec<CertificateInfo>, CacheError> {
        Ok(self.snapshot()?.certificates)
    }

    pub fn get_cached_signing_identities(
        &self,
        config: &AppConfig,
    ) -> Result<Vec<SigningIdentity>, CacheError> {
        let snapshot = self.snapshot()?;
        Ok(build_signing_identities(
            &snapshot.tokens,
            &snapshot.certificates,
            config,
        ))
    }

    pub fn refresh_signing_identities(
        &self,
        config: &AppConfig,
    ) -> Result<Vec<SigningIdentity>, CacheError> {
        let snapshot = self.refresh_tokens_and_certificates(config)?;
        Ok(build_signing_identities(
            &snapshot.tokens,
            &snapshot.certificates,
            config,
        ))
    }

    pub fn find_certificate_der_base64(
        &self,
        slot_id: u64,
        certificate_id: &str,
    ) -> Result<Option<String>, CacheError> {
        Ok(self
            .snapshot()?
            .certificates
            .into_iter()
            .find(|certificate| {
                certificate.slot_id == slot_id
                    && certificate
                        .id
                        .as_deref()
                        .is_some_and(|id| id.eq_ignore_ascii_case(certificate_id))
            })
            .and_then(|certificate| certificate.certificate_der_base64))
    }

    pub fn refresh_tokens_and_certificates(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        self.refresh_deep(config, false)
    }

    pub fn force_refresh_tokens_and_certificates(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        self.refresh_deep(config, true)
    }

    pub fn refresh_fast(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let started = Instant::now();
        let _refresh_guard = self.lock_refresh("refresh_fast")?;

        let library_path = self.resolve_library_path(config)?;
        let Some(library_path_value) = library_path.as_deref() else {
            let state = self.update_state(|state| {
                state.tokens.clear();
                state.certificates.clear();
                state.loaded_at = Some(Utc::now());
                state.expires_at = Some(Utc::now() + Duration::seconds(CACHE_TTL_SECONDS));
                state.pkcs11_library_path = None;
                state.token_fingerprint = None;
                state.last_event = Some("driver_missing".to_owned());
                state.last_event_at = Some(Utc::now());
            })?;
            info!(
                signing_step = "refresh_fast",
                elapsed_ms = started.elapsed().as_millis() as u64,
                watcher_event = "driver_missing",
                "fast token refresh completed without PKCS#11 library"
            );
            return Ok(state);
        };
        let tokens =
            provider::list_tokens_with_library_path(library_path_value).inspect_err(|_| {
                let _ = self.invalidate();
            })?;
        let new_fingerprint = token_fingerprint(&tokens);
        let previous = self.snapshot().unwrap_or_default();
        let same_token = previous.token_fingerprint.as_deref() == Some(new_fingerprint.as_str())
            && previous.pkcs11_library_path == library_path;
        let event = token_event(&previous.tokens, &tokens, same_token);
        let now = Utc::now();
        let state = self.update_state(|state| {
            state.tokens = tokens;
            state.loaded_at = Some(now);
            state.expires_at = Some(now + Duration::seconds(CACHE_TTL_SECONDS));
            state.pkcs11_library_path = library_path;
            state.token_fingerprint = Some(new_fingerprint);
            state.watcher_active = true;
            state.last_event = Some(event.clone());
            state.last_event_at = Some(now);
            if !same_token {
                state.certificates.clear();
                state.certificates_loaded_at = None;
            }
        })?;

        persist_cache(&state)?;

        info!(
            signing_step = "refresh_fast",
            elapsed_ms = started.elapsed().as_millis() as u64,
            token_count = state.tokens.len(),
            watcher_event = %event,
            refresh_skipped_same_serial = same_token,
            pkcs11_library_path = ?state.pkcs11_library_path,
            "fast token cache refreshed"
        );

        Ok(state)
    }

    fn refresh_deep(
        &self,
        config: &AppConfig,
        force: bool,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let started = Instant::now();
        let _refresh_guard = self.lock_refresh("refresh_deep")?;

        let previous = self.snapshot().unwrap_or_default();
        if !force && cache_valid(&previous) && previous.certificates_loaded_at.is_some() {
            let state = self.update_state(|state| {
                state.cache_hits = state.cache_hits.saturating_add(1);
                state.last_event = Some("cache_hit".to_owned());
                state.last_event_at = Some(Utc::now());
            })?;
            info!(
                signing_step = "refresh_deep",
                elapsed_ms = started.elapsed().as_millis() as u64,
                cache_hit = true,
                "deep token/certificate refresh skipped because cache is valid"
            );
            return Ok(state);
        }

        let library_path = self.resolve_library_path(config)?;
        let Some(library_path_value) = library_path.as_deref() else {
            return Err(ProviderError::LibraryNotFound.into());
        };
        let tokens =
            provider::list_tokens_with_library_path(library_path_value).inspect_err(|_| {
                let _ = self.invalidate();
            })?;
        let new_fingerprint = token_fingerprint(&tokens);
        let previous = self.snapshot().unwrap_or_default();
        let same_token = previous.token_fingerprint.as_deref() == Some(new_fingerprint.as_str())
            && previous.pkcs11_library_path == library_path;

        if !force
            && same_token
            && cache_valid(&previous)
            && previous.certificates_loaded_at.is_some()
        {
            let state = self.update_state(|state| {
                state.tokens = tokens;
                state.loaded_at = Some(Utc::now());
                state.expires_at = Some(Utc::now() + Duration::seconds(CACHE_TTL_SECONDS));
                state.cache_hits = state.cache_hits.saturating_add(1);
                state.last_event = Some("refresh_skipped_same_serial".to_owned());
                state.last_event_at = Some(Utc::now());
            })?;
            info!(
                signing_step = "refresh_deep",
                elapsed_ms = started.elapsed().as_millis() as u64,
                cache_hit = true,
                refresh_skipped_same_serial = true,
                "deep token/certificate refresh skipped because token serial is unchanged"
            );
            return Ok(state);
        }

        let certificates = provider::list_certificates_with_library_path(library_path_value)
            .inspect_err(|_| {
                let _ = self.invalidate();
            })?;
        let now = Utc::now();
        let event = token_event(&previous.tokens, &tokens, same_token);
        let state = self.update_state(|state| {
            state.tokens = tokens;
            state.certificates = certificates;
            state.loaded_at = Some(now);
            state.expires_at = Some(now + Duration::seconds(CACHE_TTL_SECONDS));
            state.certificates_loaded_at = Some(now);
            state.pkcs11_library_path = library_path;
            state.token_fingerprint = Some(new_fingerprint);
            state.watcher_active = true;
            state.last_event = Some(event.clone());
            state.last_event_at = Some(now);
            state.cache_misses = state.cache_misses.saturating_add(1);
        })?;
        persist_cache(&state)?;

        info!(
            signing_step = "refresh_deep",
            elapsed_ms = started.elapsed().as_millis() as u64,
            token_count = state.tokens.len(),
            certificate_count = state.certificates.len(),
            cache_miss = true,
            watcher_event = %event,
            pkcs11_library_path = ?state.pkcs11_library_path,
            "deep token/certificate cache refreshed"
        );

        Ok(state)
    }

    pub fn invalidate(&self) -> Result<(), CacheError> {
        *self.inner.write().map_err(|_| CacheError::StateLock)? =
            TokenCertificateCacheState::default();
        info!("token/certificate cache invalidated");
        Ok(())
    }

    pub fn record_watcher_event(
        &self,
        backend: &str,
        event: &str,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        self.update_state(|state| {
            state.watcher_active = true;
            state.watcher_backend = Some(backend.to_owned());
            state.last_event = Some(event.to_owned());
            state.last_event_at = Some(Utc::now());
        })
    }

    pub fn record_watcher_backend(
        &self,
        backend: &str,
        active: bool,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        self.update_state(|state| {
            state.watcher_backend = Some(backend.to_owned());
            state.watcher_active = active;
            state.last_event_at.get_or_insert_with(Utc::now);
        })
    }

    fn lock_refresh(&self, step: &str) -> Result<std::sync::MutexGuard<'_, ()>, CacheError> {
        match self.refresh_lock.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::WouldBlock) => {
                info!(
                    signing_step = step,
                    refresh_deduplicated = true,
                    "refresh already running; waiting for existing refresh"
                );
                self.refresh_lock
                    .lock()
                    .map_err(|_| CacheError::RefreshLock)
            }
            Err(std::sync::TryLockError::Poisoned(_)) => Err(CacheError::RefreshLock),
        }
    }

    fn update_state(
        &self,
        update: impl FnOnce(&mut TokenCertificateCacheState),
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let mut state = self.inner.write().map_err(|_| CacheError::StateLock)?;
        update(&mut state);
        Ok(state.clone())
    }

    fn resolve_library_path(&self, config: &AppConfig) -> Result<Option<String>, CacheError> {
        if let Ok(snapshot) = self.snapshot()
            && let Some(path) = snapshot.pkcs11_library_path
            && Path::new(&path).is_file()
        {
            info!(
                signing_step = "detect_pkcs11_library",
                cache_hit = true,
                pkcs11_library_path = %path,
                "PKCS#11 library reused from cache"
            );
            return Ok(Some(path));
        }

        let library = provider::detect_pkcs11_library(config).inspect_err(|_| {
            let _ = self.invalidate();
        })?;
        Ok(library.path)
    }
}

impl Default for TokenCertificateCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("token/certificate cache state lock is unavailable")]
    StateLock,
    #[error("token/certificate cache refresh lock is unavailable")]
    RefreshLock,
    #[error("could not read token/certificate cache file {path}: {source}")]
    ReadPersisted {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse token/certificate cache file {path}: {source}")]
    ParsePersisted {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not write token/certificate cache file {path}: {source}")]
    WritePersisted {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn cache_valid(state: &TokenCertificateCacheState) -> bool {
    state
        .expires_at
        .is_some_and(|expires_at| expires_at > Utc::now())
}

fn token_fingerprint(tokens: &[TokenInfo]) -> String {
    let mut parts = tokens
        .iter()
        .filter(|token| token.token_present)
        .map(|token| {
            format!(
                "{}:{}:{}",
                token.slot_id,
                token.serial_number.as_deref().unwrap_or("-"),
                token.label.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>();
    parts.sort();
    parts.join("|")
}

fn token_event(previous: &[TokenInfo], current: &[TokenInfo], same_token: bool) -> String {
    if same_token {
        return "unchanged".to_owned();
    }
    let previous_count = previous.iter().filter(|token| token.token_present).count();
    let current_count = current.iter().filter(|token| token.token_present).count();
    if current_count > previous_count {
        "insert".to_owned()
    } else if current_count < previous_count {
        "remove".to_owned()
    } else {
        "change".to_owned()
    }
}

fn persisted_cache_path() -> Result<PathBuf, CacheError> {
    let directory = AppConfig::config_directory()
        .map_err(|_| CacheError::StateLock)?
        .join(CACHE_DIRECTORY);
    Ok(directory.join(TOKEN_CERTIFICATE_CACHE_FILE))
}

fn read_persisted_cache() -> Result<Option<TokenCertificateCacheState>, CacheError> {
    let path = persisted_cache_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path).map_err(|source| CacheError::ReadPersisted {
        path: path.clone(),
        source,
    })?;
    let mut state: TokenCertificateCacheState =
        serde_json::from_str(&contents).map_err(|source| CacheError::ParsePersisted {
            path: path.clone(),
            source,
        })?;
    state.last_event = Some("persisted_cache_loaded".to_owned());
    Ok(Some(state))
}

fn persist_cache(state: &TokenCertificateCacheState) -> Result<(), CacheError> {
    let path = persisted_cache_path()?;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|source| CacheError::WritePersisted {
            path: directory.to_path_buf(),
            source,
        })?;
    }
    let json =
        serde_json::to_string_pretty(state).map_err(|source| CacheError::ParsePersisted {
            path: path.clone(),
            source,
        })?;
    fs::write(&path, json).map_err(|source| CacheError::WritePersisted { path, source })
}
