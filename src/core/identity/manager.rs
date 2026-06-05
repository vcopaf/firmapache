use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::{
    config::AppConfig,
    core::{
        cache::{CacheError, TokenCertificateCache},
        pkcs12,
    },
    models::pkcs11::{CertificateInfo, TokenInfo},
};

use super::identity::{ResolvedSigningIdentity, SigningIdentity};

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Signing identity not found")]
    NotFound,
    #[error(
        "El token o certificado seleccionado ya no está disponible. Actualice tokens/certificados."
    )]
    NotAvailable,
    #[error("El certificado seleccionado está expirado.")]
    Expired,
    #[error("Signing identity has no certificate id")]
    MissingCertificateId,
    #[error(transparent)]
    Cache(#[from] CacheError),
}

pub fn build_signing_identities(
    tokens: &[TokenInfo],
    certificates: &[CertificateInfo],
    config: &AppConfig,
) -> Vec<SigningIdentity> {
    let tokens_by_slot = tokens
        .iter()
        .map(|token| (token.slot_id, token))
        .collect::<HashMap<_, _>>();
    let default_identity_id = config.signing.default_identity_id.trim();
    let mut identities = certificates
        .iter()
        .filter_map(|certificate| {
            let certificate_id = certificate.id.clone()?;
            let token = tokens_by_slot.get(&certificate.slot_id).copied();
            let is_available = token.is_some_and(|token| token.token_present);
            let identity_id = identity_id(token, certificate.slot_id, &certificate_id);
            let is_expired = is_expired(certificate.not_after.as_deref());
            Some(SigningIdentity {
                identity_id,
                provider: "pkcs11".to_owned(),
                slot_id: certificate.slot_id,
                token_label: token.and_then(|token| token.label.clone()),
                token_model: token.and_then(|token| token.model.clone()),
                token_serial: token.and_then(|token| token.serial_number.clone()),
                token_manufacturer: token.and_then(|token| token.manufacturer.clone()),
                certificate_id: Some(certificate_id),
                certificate_label: certificate.label.clone(),
                subject: certificate.subject.clone(),
                issuer: certificate.issuer.clone(),
                serial_number: certificate.serial_number.clone(),
                not_before: certificate.not_before.clone(),
                not_after: certificate.not_after.clone(),
                is_expired,
                expires_soon: expires_soon(certificate.not_after.as_deref()),
                is_default: false,
                is_available,
                virtual_token_id: None,
                source_path: None,
                password_env: None,
                is_virtual: false,
            })
        })
        .collect::<Vec<_>>();
    identities.extend(pkcs12::provider::configured_identities(config));

    mark_default_identity(&mut identities, default_identity_id);
    if !default_identity_id.is_empty()
        && !identities
            .iter()
            .any(|identity| identity.identity_id == default_identity_id)
    {
        identities.push(unavailable_default_identity(default_identity_id));
    }
    identities.sort_by(|left, right| {
        left.token_label
            .cmp(&right.token_label)
            .then(left.token_serial.cmp(&right.token_serial))
            .then(left.subject.cmp(&right.subject))
    });
    identities
}

pub fn resolve_signing_identity(
    cache: &TokenCertificateCache,
    config: &AppConfig,
    identity_id: &str,
) -> Result<ResolvedSigningIdentity, IdentityError> {
    let snapshot = cache.snapshot()?;
    let identities = build_signing_identities(&snapshot.tokens, &snapshot.certificates, config);
    let identity = identities
        .iter()
        .find(|identity| identity.identity_id == identity_id)
        .ok_or(IdentityError::NotFound)?;
    if !identity.is_available {
        return Err(IdentityError::NotAvailable);
    }
    if identity.is_expired {
        return Err(IdentityError::Expired);
    }
    let certificate_id = identity
        .certificate_id
        .clone()
        .ok_or(IdentityError::MissingCertificateId)?;
    let certificate_der_base64 = if identity.provider == "pkcs11" {
        snapshot
            .certificates
            .into_iter()
            .find(|certificate| {
                certificate.slot_id == identity.slot_id
                    && certificate
                        .id
                        .as_deref()
                        .is_some_and(|id| id.eq_ignore_ascii_case(&certificate_id))
            })
            .and_then(|certificate| certificate.certificate_der_base64)
    } else {
        None
    };

    Ok(ResolvedSigningIdentity {
        identity_id: identity.identity_id.clone(),
        provider: identity.provider.clone(),
        slot_id: identity.slot_id,
        certificate_id,
        certificate_der_base64,
        virtual_token_id: identity.virtual_token_id.clone(),
        password_env: identity.password_env.clone(),
    })
}

fn mark_default_identity(identities: &mut [SigningIdentity], default_identity_id: &str) {
    if !default_identity_id.is_empty() {
        if let Some(identity) = identities
            .iter_mut()
            .find(|identity| identity.identity_id == default_identity_id && identity.is_available)
        {
            identity.is_default = true;
        }
        return;
    }

    let available_count = identities
        .iter()
        .filter(|identity| identity.is_available && !identity.is_expired)
        .count();
    if available_count == 1 {
        if let Some(identity) = identities
            .iter_mut()
            .find(|identity| identity.is_available && !identity.is_expired)
        {
            identity.is_default = true;
        }
    }
}

fn identity_id(token: Option<&TokenInfo>, slot_id: u64, certificate_id: &str) -> String {
    let token_part = token
        .and_then(|token| token.serial_number.as_deref())
        .filter(|serial| !serial.trim().is_empty())
        .unwrap_or("slot");
    if token_part == "slot" {
        format!("pkcs11:slot-{slot_id}:{certificate_id}")
    } else {
        format!("pkcs11:{token_part}:{slot_id}:{certificate_id}")
    }
}

fn unavailable_default_identity(identity_id: &str) -> SigningIdentity {
    SigningIdentity {
        identity_id: identity_id.to_owned(),
        provider: "pkcs11".to_owned(),
        slot_id: 0,
        token_label: Some("Token no disponible".to_owned()),
        token_model: None,
        token_serial: None,
        token_manufacturer: None,
        certificate_id: None,
        certificate_label: None,
        subject: Some("Identidad predeterminada no disponible".to_owned()),
        issuer: None,
        serial_number: None,
        not_before: None,
        not_after: None,
        is_expired: false,
        expires_soon: false,
        is_default: true,
        is_available: false,
        virtual_token_id: None,
        source_path: None,
        password_env: None,
        is_virtual: false,
    }
}

fn is_expired(value: Option<&str>) -> bool {
    parse_certificate_time(value).is_some_and(|not_after| not_after < Utc::now())
}

fn expires_soon(value: Option<&str>) -> bool {
    parse_certificate_time(value).is_some_and(|not_after| {
        not_after >= Utc::now() && not_after <= Utc::now() + Duration::days(30)
    })
}

fn parse_certificate_time(value: Option<&str>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value?)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}
