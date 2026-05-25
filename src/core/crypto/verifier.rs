use base64::{Engine as _, engine::general_purpose::STANDARD};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

use crate::models::pkcs11::{VerifyHashRequest, VerifyHashResponse};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("unsupported verification mechanism: {0}")]
    UnsupportedMechanism(String),
    #[error("certificate_der_base64 is not valid base64")]
    InvalidCertificateBase64,
    #[error("hash_base64 is not valid base64")]
    InvalidHashBase64,
    #[error("signature_base64 is not valid base64")]
    InvalidSignatureBase64,
    #[error("certificate_der_base64 is not a valid X.509 certificate")]
    InvalidCertificate,
    #[error("certificate does not contain a usable RSA public key")]
    InvalidPublicKey,
}

pub fn verify_hash(request: VerifyHashRequest) -> Result<VerifyHashResponse, VerifyError> {
    let VerifyHashRequest {
        certificate_der_base64,
        hash_base64,
        signature_base64,
        mechanism,
    } = request;
    let algorithm = mechanism.unwrap_or_else(|| "RSA_PKCS".to_owned());
    if algorithm != "RSA_PKCS" {
        return Err(VerifyError::UnsupportedMechanism(algorithm));
    }

    let certificate_der = STANDARD
        .decode(certificate_der_base64.as_bytes())
        .map_err(|_| VerifyError::InvalidCertificateBase64)?;
    let hash = STANDARD
        .decode(hash_base64.as_bytes())
        .map_err(|_| VerifyError::InvalidHashBase64)?;
    let signature = STANDARD
        .decode(signature_base64.as_bytes())
        .map_err(|_| VerifyError::InvalidSignatureBase64)?;
    let (_, certificate) =
        parse_x509_certificate(&certificate_der).map_err(|_| VerifyError::InvalidCertificate)?;
    let public_key = RsaPublicKey::from_public_key_der(certificate.public_key().raw)
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    let valid = public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &hash, &signature)
        .is_ok();

    Ok(VerifyHashResponse { valid, algorithm })
}
