use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;
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
    let slot_id = input.slot_id;
    let header = JwsHeader {
        alg: "RS256",
        x5c: [certificate_der_base64],
    };
    let compact = build_jws_compact(payload, &header, |signing_input| {
        provider::sign_rs256(
            config,
            input.slot_id,
            input.certificate_id.clone(),
            input.pin.clone(),
            signing_input,
        )
        .map_err(JwsSignError::Pkcs11)
    })?;

    info!(
        signing_step = "sign_payload_as_jws",
        elapsed_ms = started.elapsed().as_millis() as u64,
        slot_id,
        "JWS compact payload signed"
    );
    Ok(compact)
}

fn build_jws_compact<F>(
    payload: &[u8],
    header: &JwsHeader<'_>,
    signer: F,
) -> Result<String, JwsSignError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, JwsSignError>,
{
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = signer(signing_input.as_bytes())?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);

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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{PublicKeyData, SigningKey};
    use rsa::{
        RsaPrivateKey, RsaPublicKey, pkcs1v15,
        pkcs1v15::VerifyingKey,
        pkcs8::DecodePublicKey,
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::{SignatureEncoding, Signer, Verifier},
    };
    use sha2::Sha256;
    use x509_parser::parse_x509_certificate;
    use x509_parser::prelude::FromDer;
    use x509_parser::x509::SubjectPublicKeyInfo;

    struct TestRsaSigningKey {
        private_key: RsaPrivateKey,
        subject_public_key: Vec<u8>,
    }

    impl TestRsaSigningKey {
        fn generate() -> Self {
            let mut rng = OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA private key");
            let public_key = RsaPublicKey::from(&private_key);
            let public_key_der = public_key.to_public_key_der().expect("public key DER");
            let (_, spki) = SubjectPublicKeyInfo::from_der(public_key_der.as_ref()).expect("SPKI");
            let subject_public_key = spki.subject_public_key.as_ref().to_vec();

            Self {
                private_key,
                subject_public_key,
            }
        }
    }

    impl PublicKeyData for TestRsaSigningKey {
        fn der_bytes(&self) -> &[u8] {
            &self.subject_public_key
        }

        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_RSA_SHA256
        }
    }

    impl SigningKey for TestRsaSigningKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(self.private_key.clone());
            Ok(signing_key.sign(msg).to_vec())
        }
    }

    #[test]
    fn compact_jws_signature_verifies_as_rs256() {
        let signing_key = TestRsaSigningKey::generate();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("certificate params")
            .self_signed(&signing_key)
            .expect("self-signed cert");
        let certificate_der = cert.der().as_ref().to_vec();
        let certificate_der_base64 = STANDARD.encode(&certificate_der);
        let header = JwsHeader {
            alg: "RS256",
            x5c: [&certificate_der_base64],
        };

        let compact = build_jws_compact(br#"{"hola":"mundo"}"#, &header, |signing_input| {
            Ok(signing_key.sign(signing_input).expect("signing input"))
        })
        .expect("compact JWS");
        let parts = compact.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2].as_bytes())
            .expect("signature base64url");
        let (_, certificate) =
            parse_x509_certificate(&certificate_der).expect("parse generated cert");
        let public_key = RsaPublicKey::from_public_key_der(certificate.public_key().raw)
            .expect("RSA public key");
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature = pkcs1v15::Signature::try_from(signature.as_slice()).expect("signature");

        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("RS256 signature verifies");
    }
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
