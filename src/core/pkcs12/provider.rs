use std::{env, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{hash::MessageDigest, pkcs12::Pkcs12, sign::Signer};
use tracing::warn;
use x509_parser::{parse_x509_certificate, time::ASN1Time};

use crate::{
    config::{AppConfig, Pkcs12TokenConfig},
    core::identity::SigningIdentity,
};

use super::Pkcs12Error;

pub fn configured_identities(config: &AppConfig) -> Vec<SigningIdentity> {
    config
        .development
        .pkcs12_tokens
        .iter()
        .map(|token| identity_for_token(token))
        .collect()
}

pub fn certificate_der_base64(
    config: &AppConfig,
    identity_id: &str,
    password: &str,
) -> Result<String, Pkcs12Error> {
    let token = token_for_identity(config, identity_id)?;
    let loaded = load_token(token, password)?;
    Ok(STANDARD.encode(loaded.certificate_der))
}

pub fn sign_rs256(
    config: &AppConfig,
    identity_id: &str,
    password: &str,
    data: &[u8],
) -> Result<Vec<u8>, Pkcs12Error> {
    let token = token_for_identity(config, identity_id)?;
    let loaded = load_token(token, password)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &loaded.private_key)
        .map_err(|_| Pkcs12Error::SigningFailed)?;
    signer
        .update(data)
        .map_err(|_| Pkcs12Error::SigningFailed)?;
    signer.sign_to_vec().map_err(|_| Pkcs12Error::SigningFailed)
}

pub fn test_token(token: &Pkcs12TokenConfig) -> Result<SigningIdentity, Pkcs12Error> {
    let password = env::var(token.password_env.trim())
        .map_err(|_| Pkcs12Error::PasswordEnvironmentVariableNotFound)?;
    let loaded = load_token(token, &password)?;
    Ok(identity_from_certificate(
        token,
        &loaded.certificate_der,
        true,
    ))
}

fn identity_for_token(token: &Pkcs12TokenConfig) -> SigningIdentity {
    if !Path::new(&token.path).exists() {
        return unavailable_identity(token, "Archivo PKCS#12 no disponible", false);
    }
    let password = match env::var(token.password_env.trim()) {
        Ok(password) if !password.is_empty() => password,
        _ => return unavailable_identity(token, "Contraseña PKCS#12 no disponible", true),
    };

    match load_token(token, &password) {
        Ok(loaded) => identity_from_certificate(token, &loaded.certificate_der, true),
        Err(error) => {
            warn!(
                token_id = %token.id,
                error = %error,
                "could not load configured PKCS#12 development token"
            );
            unavailable_identity(token, "Token virtual PKCS#12 no disponible", true)
        }
    }
}

fn token_for_identity<'a>(
    config: &'a AppConfig,
    identity_id: &str,
) -> Result<&'a Pkcs12TokenConfig, Pkcs12Error> {
    config
        .development
        .pkcs12_tokens
        .iter()
        .find(|token| identity_id.starts_with(&format!("pkcs12:{}:", token.id)))
        .ok_or(Pkcs12Error::TokenNotFound)
}

struct LoadedPkcs12 {
    certificate_der: Vec<u8>,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
}

fn load_token(token: &Pkcs12TokenConfig, password: &str) -> Result<LoadedPkcs12, Pkcs12Error> {
    if !Path::new(&token.path).exists() {
        return Err(Pkcs12Error::PathNotFound(token.path.clone()));
    }
    let der = fs::read(&token.path)?;
    let parsed = Pkcs12::from_der(&der)
        .map_err(|_| Pkcs12Error::Parse)?
        .parse2(password)
        .map_err(|_| Pkcs12Error::Parse)?;
    let cert = parsed.cert.ok_or(Pkcs12Error::CertificateNotFound)?;
    let private_key = parsed.pkey.ok_or(Pkcs12Error::PrivateKeyNotFound)?;
    let certificate_der = cert.to_der().map_err(|_| Pkcs12Error::Parse)?;

    Ok(LoadedPkcs12 {
        certificate_der,
        private_key,
    })
}

fn identity_from_certificate(
    token: &Pkcs12TokenConfig,
    certificate_der: &[u8],
    is_available: bool,
) -> SigningIdentity {
    let parsed = parse_x509_certificate(certificate_der)
        .ok()
        .map(|(_, parsed)| parsed);
    let serial = parsed
        .as_ref()
        .map(|certificate| certificate.tbs_certificate.raw_serial_as_string())
        .unwrap_or_else(|| "certificate".to_owned());
    let is_expired = parsed
        .as_ref()
        .is_some_and(|certificate| certificate.validity().is_valid() == false);

    SigningIdentity {
        identity_id: format!("pkcs12:{}:{serial}", token.id),
        provider: "pkcs12".to_owned(),
        slot_id: 0,
        token_label: Some(token.label.clone()),
        token_model: Some("PKCS#12 DEV".to_owned()),
        token_serial: Some(token.id.clone()),
        token_manufacturer: Some("MiniFirmador".to_owned()),
        certificate_id: Some(serial.clone()),
        certificate_label: Some(token.label.clone()),
        subject: parsed
            .as_ref()
            .map(|certificate| certificate.subject().to_string()),
        issuer: parsed
            .as_ref()
            .map(|certificate| certificate.issuer().to_string()),
        serial_number: Some(serial),
        not_before: parsed
            .as_ref()
            .map(|certificate| format_certificate_time(certificate.validity().not_before)),
        not_after: parsed
            .as_ref()
            .map(|certificate| format_certificate_time(certificate.validity().not_after)),
        is_expired,
        expires_soon: false,
        is_default: false,
        is_available,
        virtual_token_id: Some(token.id.clone()),
        source_path: Some(token.path.clone()),
        password_env: Some(token.password_env.clone()),
        is_virtual: true,
    }
}

fn unavailable_identity(
    token: &Pkcs12TokenConfig,
    reason: &str,
    is_available: bool,
) -> SigningIdentity {
    SigningIdentity {
        identity_id: format!("pkcs12:{}:manual", token.id),
        provider: "pkcs12".to_owned(),
        slot_id: 0,
        token_label: Some(token.label.clone()),
        token_model: Some("PKCS#12 DEV".to_owned()),
        token_serial: Some(token.id.clone()),
        token_manufacturer: Some("MiniFirmador".to_owned()),
        certificate_id: Some("manual".to_owned()),
        certificate_label: Some(token.label.clone()),
        subject: Some(reason.to_owned()),
        issuer: None,
        serial_number: None,
        not_before: None,
        not_after: None,
        is_expired: false,
        expires_soon: false,
        is_default: false,
        is_available,
        virtual_token_id: Some(token.id.clone()),
        source_path: Some(token.path.clone()),
        password_env: Some(token.password_env.clone()),
        is_virtual: true,
    }
}

fn format_certificate_time(value: ASN1Time) -> String {
    let date_time = value.to_datetime();

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date_time.year(),
        u8::from(date_time.month()),
        date_time.day(),
        date_time.hour(),
        date_time.minute(),
        date_time.second()
    )
}
