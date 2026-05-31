use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;
use thiserror::Error;
use tracing::info;

use crate::{
    config::AppConfig,
    core::{
        cache::{CacheError, TokenCertificateCache},
        pkcs11::provider::{self, ProviderError},
    },
    models::{
        compatible::{CompatibleOutputFile, CompatibleSignResponse},
        pkcs11::SignHashRequest,
        signing::{ApproveSigningSessionInput, SigningSessionFile},
    },
};

#[derive(Debug, Error)]
pub enum JwsSignError {
    #[error("Missing certificate selection")]
    MissingCertificateSelection,
    #[error("Missing PIN")]
    MissingPin,
    #[error("Certificate not found")]
    CertificateNotFound,
    #[error("Invalid base64 input")]
    InvalidBase64,
    #[error("JWS signing failed: {0}")]
    Header(#[from] serde_json::Error),
    #[error(transparent)]
    Pkcs11(#[from] ProviderError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    x5c: [&'a str; 1],
}

pub fn sign_files(
    config: &AppConfig,
    files: &[SigningSessionFile],
    input: ApproveSigningSessionInput,
) -> Result<CompatibleSignResponse, JwsSignError> {
    validate_signing_input(&input)?;
    let certificate_der_base64 =
        certificate_der_base64(config, input.slot_id, &input.certificate_id)?;

    let files = files
        .iter()
        .map(|file| {
            let payload = STANDARD
                .decode(file.content_base64.as_bytes())
                .map_err(|_| JwsSignError::InvalidBase64)?;
            sign_payload_compact(config, &payload, &certificate_der_base64, &input).map(
                |jws_compact| CompatibleOutputFile {
                    base64: STANDARD.encode(jws_compact.as_bytes()),
                    name: file.name.clone(),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompatibleSignResponse { files })
}

pub fn sign_files_with_cache(
    config: &AppConfig,
    files: &[SigningSessionFile],
    input: ApproveSigningSessionInput,
    cache: &TokenCertificateCache,
) -> Result<CompatibleSignResponse, JwsSignError> {
    validate_signing_input(&input)?;
    let certificate_der_base64 =
        certificate_der_base64_with_cache(config, cache, input.slot_id, &input.certificate_id)?;

    let files = files
        .iter()
        .map(|file| {
            let payload = STANDARD
                .decode(file.content_base64.as_bytes())
                .map_err(|_| JwsSignError::InvalidBase64)?;
            sign_payload_compact(config, &payload, &certificate_der_base64, &input).map(
                |jws_compact| CompatibleOutputFile {
                    base64: STANDARD.encode(jws_compact.as_bytes()),
                    name: file.name.clone(),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompatibleSignResponse { files })
}

pub fn sign_payload_base64(
    config: &AppConfig,
    payload: &[u8],
    input: ApproveSigningSessionInput,
) -> Result<String, JwsSignError> {
    validate_signing_input(&input)?;
    let certificate_der_base64 =
        certificate_der_base64(config, input.slot_id, &input.certificate_id)?;
    sign_payload_compact(config, payload, &certificate_der_base64, &input)
        .map(|jws_compact| STANDARD.encode(jws_compact.as_bytes()))
}

pub fn sign_payload_base64_with_cache(
    config: &AppConfig,
    payload: &[u8],
    input: ApproveSigningSessionInput,
    cache: &TokenCertificateCache,
) -> Result<String, JwsSignError> {
    let started = Instant::now();
    validate_signing_input(&input)?;
    let certificate_der_base64 =
        certificate_der_base64_with_cache(config, cache, input.slot_id, &input.certificate_id)?;
    let result = sign_payload_compact(config, payload, &certificate_der_base64, &input)
        .map(|jws_compact| STANDARD.encode(jws_compact.as_bytes()));
    info!(
        signing_step = "sign_payload_as_jws",
        elapsed_ms = started.elapsed().as_millis() as u64,
        slot_id = input.slot_id,
        "JWS payload signing completed"
    );
    result
}

fn sign_payload_compact(
    config: &AppConfig,
    payload: &[u8],
    certificate_der_base64: &str,
    input: &ApproveSigningSessionInput,
) -> Result<String, JwsSignError> {
    let started = Instant::now();
    let header = JwsHeader {
        alg: "RS256",
        typ: "JWT",
        x5c: [certificate_der_base64],
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let hash = Sha256::digest(signing_input.as_bytes());

    let signature = provider::sign_hash(
        config,
        SignHashRequest {
            slot_id: input.slot_id,
            pin: input.pin.clone(),
            hash_base64: STANDARD.encode(hash),
            mechanism: Some("RSA_PKCS".to_owned()),
            certificate_id: Some(input.certificate_id.clone()),
        },
    )?;
    let signature = STANDARD
        .decode(signature.signature_base64.as_bytes())
        .map_err(|_| JwsSignError::InvalidBase64)?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);

    info!(
        signing_step = "sign_payload_as_jws",
        elapsed_ms = started.elapsed().as_millis() as u64,
        slot_id = input.slot_id,
        "JWS compact payload signed"
    );
    Ok(format!("{signing_input}.{encoded_signature}"))
}

fn validate_signing_input(input: &ApproveSigningSessionInput) -> Result<(), JwsSignError> {
    if input.certificate_id.trim().is_empty() {
        return Err(JwsSignError::MissingCertificateSelection);
    }
    if input.pin.is_empty() {
        return Err(JwsSignError::MissingPin);
    }
    Ok(())
}

fn certificate_der_base64(
    config: &AppConfig,
    slot_id: u64,
    certificate_id: &str,
) -> Result<String, JwsSignError> {
    provider::list_certificates(config)?
        .into_iter()
        .find(|certificate| {
            certificate.slot_id == slot_id
                && certificate
                    .id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(certificate_id))
        })
        .and_then(|certificate| certificate.certificate_der_base64)
        .ok_or(JwsSignError::CertificateNotFound)
}

fn certificate_der_base64_with_cache(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    slot_id: u64,
    certificate_id: &str,
) -> Result<String, JwsSignError> {
    if let Some(certificate_der_base64) =
        cache.find_certificate_der_base64(slot_id, certificate_id)?
    {
        info!(
            slot_id,
            certificate_id,
            signing_step = "certificate_cache_lookup",
            cache_hit = true,
            "certificate DER loaded from cache"
        );
        return Ok(certificate_der_base64);
    }

    info!(
        slot_id,
        certificate_id,
        signing_step = "certificate_cache_lookup",
        cache_hit = false,
        "certificate DER not found in cache; refreshing"
    );
    let refreshed = cache.refresh_tokens_and_certificates(config)?;
    refreshed
        .certificates
        .into_iter()
        .find(|certificate| {
            certificate.slot_id == slot_id
                && certificate
                    .id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(certificate_id))
        })
        .and_then(|certificate| certificate.certificate_der_base64)
        .ok_or(JwsSignError::CertificateNotFound)
}
