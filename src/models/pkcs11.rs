use serde::Serialize;

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
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}
