use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rsa::{
    RsaPublicKey, pkcs1v15, pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x509_parser::parse_x509_certificate;

#[derive(Debug, Serialize)]
pub struct JwsValidationReport {
    pub detected_input: String,
    pub alg: Option<String>,
    pub has_x5c: bool,
    pub certificate_subject: Option<String>,
    pub payload_size_bytes: usize,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum JwsValidationError {
    #[error("JWS file is empty")]
    Empty,
    #[error("input is not JWS compact or Base64(JWS compact)")]
    InvalidCompact,
    #[error("JWS header is not valid Base64URL")]
    InvalidHeaderBase64,
    #[error("JWS payload is not valid Base64URL")]
    InvalidPayloadBase64,
    #[error("JWS signature is not valid Base64URL")]
    InvalidSignatureBase64,
    #[error("JWS header is not valid JSON")]
    InvalidHeaderJson,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: Option<String>,
    x5c: Option<Vec<String>>,
}

pub fn validate_jws_bytes(input: &[u8]) -> Result<JwsValidationReport, JwsValidationError> {
    let raw = std::str::from_utf8(input)
        .map(str::trim)
        .map_err(|_| JwsValidationError::InvalidCompact)?;
    if raw.is_empty() {
        return Err(JwsValidationError::Empty);
    }

    let (compact, detected_input) = detect_compact(raw)?;
    let parts = compact.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(JwsValidationError::InvalidCompact);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| JwsValidationError::InvalidHeaderBase64)?;
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| JwsValidationError::InvalidPayloadBase64)?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| JwsValidationError::InvalidSignatureBase64)?;
    let header = serde_json::from_slice::<JwsHeader>(&header_bytes)
        .map_err(|_| JwsValidationError::InvalidHeaderJson)?;

    let mut report = JwsValidationReport {
        detected_input,
        alg: header.alg.clone(),
        has_x5c: header
            .x5c
            .as_ref()
            .is_some_and(|certificates| !certificates.is_empty()),
        certificate_subject: None,
        payload_size_bytes: payload.len(),
        valid: false,
        error: None,
    };

    if header.alg.as_deref() != Some("RS256") {
        report.error = Some("Unsupported or missing alg; expected RS256".to_owned());
        return Ok(report);
    }

    let Some(certificate_base64) = header
        .x5c
        .as_ref()
        .and_then(|certificates| certificates.first())
    else {
        report.error = Some("Missing x5c certificate".to_owned());
        return Ok(report);
    };

    let certificate_der = match STANDARD.decode(certificate_base64.as_bytes()) {
        Ok(certificate_der) => certificate_der,
        Err(_) => {
            report.error = Some("x5c certificate is not valid Base64".to_owned());
            return Ok(report);
        }
    };
    let (_, certificate) = match parse_x509_certificate(&certificate_der) {
        Ok(certificate) => certificate,
        Err(_) => {
            report.error = Some("x5c certificate is not a valid X.509 certificate".to_owned());
            return Ok(report);
        }
    };
    report.certificate_subject = Some(certificate.subject().to_string());

    let public_key = match RsaPublicKey::from_public_key_der(certificate.public_key().raw) {
        Ok(public_key) => public_key,
        Err(_) => {
            report.error = Some("certificate does not contain a usable RSA public key".to_owned());
            return Ok(report);
        }
    };
    let signature = match pkcs1v15::Signature::try_from(signature.as_slice()) {
        Ok(signature) => signature,
        Err(_) => {
            report.error = Some("signature has invalid RSA size".to_owned());
            return Ok(report);
        }
    };
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    report.valid = verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .is_ok();
    if !report.valid {
        report.error = Some("RS256 signature verification failed".to_owned());
    }

    Ok(report)
}

fn detect_compact(raw: &str) -> Result<(String, String), JwsValidationError> {
    if raw.split('.').count() == 3 {
        return Ok((raw.to_owned(), "jws_compact".to_owned()));
    }

    let decoded = STANDARD
        .decode(raw.as_bytes())
        .map_err(|_| JwsValidationError::InvalidCompact)?;
    let decoded = String::from_utf8(decoded).map_err(|_| JwsValidationError::InvalidCompact)?;
    if decoded.split('.').count() != 3 {
        return Err(JwsValidationError::InvalidCompact);
    }
    Ok((decoded, "base64_jws_compact".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_jws_input() {
        let error = validate_jws_bytes(b"hello").expect_err("plain text should fail");

        assert!(matches!(error, JwsValidationError::InvalidCompact));
    }
}
