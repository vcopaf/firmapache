use std::{
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;
use tracing::info;

use crate::{
    config::AppConfig,
    core::identity::{SigningIdentity, build_signing_identities},
    core::pkcs11::provider::{self, ProviderError},
    models::pkcs11::{CertificateInfo, TokenInfo},
};

#[derive(Clone)]
pub struct TokenCertificateCache {
    inner: Arc<RwLock<TokenCertificateCacheState>>,
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TokenCertificateCacheState {
    pub tokens: Vec<TokenInfo>,
    pub certificates: Vec<CertificateInfo>,
    pub loaded_at: Option<DateTime<Utc>>,
    pub pkcs11_library_path: Option<String>,
}

impl TokenCertificateCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TokenCertificateCacheState::default())),
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn snapshot(&self) -> Result<TokenCertificateCacheState, CacheError> {
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
        let started = Instant::now();
        let _refresh_guard = self
            .refresh_lock
            .lock()
            .map_err(|_| CacheError::RefreshLock)?;

        let library = provider::detect_pkcs11_library(config).inspect_err(|_| {
            let _ = self.invalidate();
        })?;
        let library_path = library.path.clone();
        let tokens = provider::list_tokens(config).inspect_err(|_| {
            let _ = self.invalidate();
        })?;
        let certificates = provider::list_certificates(config).inspect_err(|_| {
            let _ = self.invalidate();
        })?;
        let state = TokenCertificateCacheState {
            tokens,
            certificates,
            loaded_at: Some(Utc::now()),
            pkcs11_library_path: library_path,
        };

        *self.inner.write().map_err(|_| CacheError::StateLock)? = state.clone();

        info!(
            signing_step = "refresh_tokens_and_certificates",
            elapsed_ms = started.elapsed().as_millis() as u64,
            token_count = state.tokens.len(),
            certificate_count = state.certificates.len(),
            pkcs11_library_path = ?state.pkcs11_library_path,
            "token/certificate cache refreshed"
        );

        Ok(state)
    }

    pub fn invalidate(&self) -> Result<(), CacheError> {
        *self.inner.write().map_err(|_| CacheError::StateLock)? =
            TokenCertificateCacheState::default();
        info!("token/certificate cache invalidated");
        Ok(())
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
}
