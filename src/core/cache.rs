use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::AppConfig,
    core::{identity, pkcs11::provider},
    models::pkcs11::{CertificateInfo, TokenInfo},
};

const CACHE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error(transparent)]
    Provider(#[from] provider::ProviderError),
    #[error("token/certificate cache state lock is unavailable")]
    StateLock,
}

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Default)]
pub struct TokenCertificateCache {
    state: Arc<RwLock<TokenCertificateCacheState>>,
    refresh_lock: Arc<Mutex<()>>,
}

impl TokenCertificateCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Result<TokenCertificateCacheState, CacheError> {
        self.state
            .read()
            .map(|state| state.clone())
            .map_err(|_| CacheError::StateLock)
    }

    pub fn invalidate(&self) -> Result<(), CacheError> {
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.tokens.clear();
        state.certificates.clear();
        state.loaded_at = None;
        state.expires_at = None;
        state.certificates_loaded_at = None;
        state.token_fingerprint = None;
        Ok(())
    }

    pub fn get_cached_tokens(&self) -> Result<Vec<TokenInfo>, CacheError> {
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.cache_hits = state.cache_hits.saturating_add(1);
        Ok(state.tokens.clone())
    }

    pub fn get_cached_certificates(&self) -> Result<Vec<CertificateInfo>, CacheError> {
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.cache_hits = state.cache_hits.saturating_add(1);
        Ok(state.certificates.clone())
    }

    pub fn find_certificate_der_base64(
        &self,
        slot_id: u64,
        certificate_id: &str,
    ) -> Result<Option<String>, CacheError> {
        let state = self.state.read().map_err(|_| CacheError::StateLock)?;
        Ok(state.certificates.iter().find_map(|certificate| {
            (certificate.slot_id == slot_id
                && certificate
                    .id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(certificate_id)))
            .then(|| certificate.certificate_der_base64.clone())
            .flatten()
        }))
    }

    pub fn get_cached_signing_identities(
        &self,
        config: &AppConfig,
    ) -> Result<Vec<identity::SigningIdentity>, CacheError> {
        let state = self.state.read().map_err(|_| CacheError::StateLock)?;
        Ok(identity::build_signing_identities(
            &state.tokens,
            &state.certificates,
            config,
        ))
    }

    pub fn refresh_fast(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let _refresh_guard = self
            .refresh_lock
            .lock()
            .map_err(|_| CacheError::StateLock)?;
        let library = provider::detect_pkcs11_library_for_token(config)?;
        let library_path = library
            .path
            .ok_or(provider::ProviderError::LibraryNotFound)?;
        let tokens = provider::list_tokens_with_library_path(&library_path)?;
        self.update_tokens(tokens, Some(library_path))
    }

    pub fn refresh_tokens_and_certificates(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let snapshot = self.snapshot()?;
        if snapshot
            .expires_at
            .is_some_and(|expires_at| expires_at > Utc::now())
            && snapshot.certificates_loaded_at.is_some()
        {
            return Ok(snapshot);
        }
        self.force_refresh_tokens_and_certificates(config)
    }

    pub fn force_refresh_tokens_and_certificates(
        &self,
        config: &AppConfig,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let _refresh_guard = self
            .refresh_lock
            .lock()
            .map_err(|_| CacheError::StateLock)?;
        let library = provider::detect_pkcs11_library_for_token(config)?;
        let library_path = library
            .path
            .ok_or(provider::ProviderError::LibraryNotFound)?;
        let tokens = provider::list_tokens_with_library_path(&library_path)?;
        let certificates = provider::list_certificates_with_library_path(&library_path)?;
        self.update_all(tokens, certificates, Some(library_path))
    }

    pub fn refresh_signing_identities(
        &self,
        config: &AppConfig,
    ) -> Result<Vec<identity::SigningIdentity>, CacheError> {
        self.refresh_tokens_and_certificates(config)?;
        self.get_cached_signing_identities(config)
    }

    pub fn record_watcher_backend(&self, backend: &str, active: bool) -> Result<(), CacheError> {
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.watcher_backend = Some(backend.to_owned());
        state.watcher_active = active;
        Ok(())
    }

    pub fn record_watcher_event(&self, backend: &str, event: &str) -> Result<(), CacheError> {
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.watcher_backend = Some(backend.to_owned());
        state.watcher_active = true;
        state.last_event = Some(event.to_owned());
        state.last_event_at = Some(Utc::now());
        Ok(())
    }

    fn update_tokens(
        &self,
        tokens: Vec<TokenInfo>,
        library_path: Option<String>,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let now = Utc::now();
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.tokens = tokens;
        state.loaded_at = Some(now);
        state.expires_at = Some(now + Duration::seconds(CACHE_TTL_SECONDS));
        state.pkcs11_library_path = library_path;
        state.token_fingerprint = Some(token_fingerprint(&state.tokens, &state.certificates));
        state.cache_misses = state.cache_misses.saturating_add(1);
        Ok(state.clone())
    }

    fn update_all(
        &self,
        tokens: Vec<TokenInfo>,
        certificates: Vec<CertificateInfo>,
        library_path: Option<String>,
    ) -> Result<TokenCertificateCacheState, CacheError> {
        let now = Utc::now();
        let fingerprint = token_fingerprint(&tokens, &certificates);
        let mut state = self.state.write().map_err(|_| CacheError::StateLock)?;
        state.tokens = tokens;
        state.certificates = certificates;
        state.loaded_at = Some(now);
        state.expires_at = Some(now + Duration::seconds(CACHE_TTL_SECONDS));
        state.certificates_loaded_at = Some(now);
        state.pkcs11_library_path = library_path;
        state.token_fingerprint = Some(fingerprint);
        state.cache_misses = state.cache_misses.saturating_add(1);
        Ok(state.clone())
    }
}

fn token_fingerprint(tokens: &[TokenInfo], certificates: &[CertificateInfo]) -> String {
    let mut digest = Sha256::new();
    if let Ok(serialized) = serde_json::to_vec(&(tokens, certificates)) {
        digest.update(serialized);
    }
    format!("{:x}", digest.finalize())
}
