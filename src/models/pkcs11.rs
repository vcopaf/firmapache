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
