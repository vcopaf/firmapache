use std::{env, time::Instant};

use thiserror::Error;
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    core::{
        cache::{CacheError, TokenCertificateCache},
        identity::{self, IdentityError},
        signing::{
            compatible,
            session_manager::{self, SigningSessionError},
        },
    },
    models::{
        compatible::{CompatibleSignRequest, CompatibleSignResponse},
        signing::ApproveSigningSessionInput,
    },
};

pub enum DevelopmentAutoSign {
    Signed(CompatibleSignResponse),
    Fallback(String),
    NotEnabled,
}

pub fn try_auto_sign(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    request: CompatibleSignRequest,
) -> Result<DevelopmentAutoSign, DevelopmentError> {
    let development = &config.development;
    if !development.enabled {
        return Ok(DevelopmentAutoSign::NotEnabled);
    }
    if !development.auto_sign {
        return Ok(DevelopmentAutoSign::NotEnabled);
    }

    let started = Instant::now();
    let result = try_auto_sign_inner(config, cache, request);
    match result {
        Ok(response) => {
            info!(
                signing_step = "development_auto_sign",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "development auto-sign completed"
            );
            Ok(DevelopmentAutoSign::Signed(response))
        }
        Err(error) if development.fallback_to_modal => {
            warn!(
                error = %error,
                signing_step = "development_auto_sign",
                "development auto-sign failed; falling back to modal"
            );
            Ok(DevelopmentAutoSign::Fallback(error.to_string()))
        }
        Err(error) => Err(error),
    }
}

fn try_auto_sign_inner(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    request: CompatibleSignRequest,
) -> Result<CompatibleSignResponse, DevelopmentError> {
    let identity_id = config.development.default_identity_id.trim();
    if identity_id.is_empty() {
        return Err(DevelopmentError::DefaultIdentityNotConfigured);
    }

    let prepared = compatible::prepare_sign_request(request)?;
    let identity = resolve_development_identity(cache, config, identity_id)?;
    let secret_env = if identity.provider == "pkcs12" {
        identity
            .password_env
            .as_deref()
            .ok_or(DevelopmentError::Pkcs12PasswordEnvironmentVariableNotFound)?
    } else {
        config.development.pin_env.trim()
    };
    let pin = env::var(secret_env).map_err(|_| {
        if identity.provider == "pkcs12" {
            DevelopmentError::Pkcs12PasswordEnvironmentVariableNotFound
        } else {
            DevelopmentError::PinEnvironmentVariableNotFound
        }
    })?;
    if pin.is_empty() {
        return if identity.provider == "pkcs12" {
            Err(DevelopmentError::Pkcs12PasswordEnvironmentVariableNotFound)
        } else {
            Err(DevelopmentError::PinEnvironmentVariableNotFound)
        };
    }

    session_manager::sign_prepared_files(
        config,
        cache,
        &prepared.files,
        &prepared.format,
        ApproveSigningSessionInput {
            slot_id: identity.slot_id,
            certificate_id: identity.certificate_id,
            pin,
            identity_id: Some(identity.identity_id),
            provider: Some(identity.provider),
        },
    )
    .map_err(DevelopmentError::AutoSignFailed)
}

fn resolve_development_identity(
    cache: &TokenCertificateCache,
    config: &AppConfig,
    identity_id: &str,
) -> Result<identity::ResolvedSigningIdentity, DevelopmentError> {
    match identity::resolve_signing_identity(cache, config, identity_id) {
        Ok(identity) => Ok(identity),
        Err(IdentityError::NotFound | IdentityError::NotAvailable | IdentityError::Cache(_)) => {
            let _ = cache.refresh_tokens_and_certificates(config);
            identity::resolve_signing_identity(cache, config, identity_id)
                .map_err(|_| DevelopmentError::IdentityNotAvailable)
        }
        Err(IdentityError::Expired) => Err(DevelopmentError::IdentityNotAvailable),
        Err(error) => Err(DevelopmentError::Identity(error)),
    }
}

#[derive(Debug, Error)]
pub enum DevelopmentError {
    #[error("Development mode is disabled")]
    Disabled,
    #[error("Development auto-sign is disabled")]
    AutoSignDisabled,
    #[error("Development default identity is not configured")]
    DefaultIdentityNotConfigured,
    #[error("Development identity is not available")]
    IdentityNotAvailable,
    #[error("Development PIN environment variable not found")]
    PinEnvironmentVariableNotFound,
    #[error("PKCS#12 password environment variable not found")]
    Pkcs12PasswordEnvironmentVariableNotFound,
    #[error("Development auto-sign failed: {0}")]
    AutoSignFailed(#[source] SigningSessionError),
    #[error(transparent)]
    Compatible(#[from] compatible::CompatibleSignError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}
