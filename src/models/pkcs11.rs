use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct Pkcs11LibraryInfo {
    pub found: bool,
    pub path: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenInfo {
    pub slot_id: u64,
    pub token_present: bool,
    pub label: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CertificateInfo {
    pub slot_id: u64,
    pub id: Option<String>,
    pub label: Option<String>,
    pub certificate_der_base64: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

#[derive(Deserialize)]
pub struct SignHashRequest {
    pub slot_id: u64,
    pub pin: String,
    pub hash_base64: String,
    pub mechanism: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignHashResponse {
    pub slot_id: u64,
    pub signature_base64: String,
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct VerifyHashRequest {
    pub certificate_der_base64: String,
    pub hash_base64: String,
    pub signature_base64: String,
    pub mechanism: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyHashResponse {
    pub valid: bool,
    pub algorithm: String,
}
