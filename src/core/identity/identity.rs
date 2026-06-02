use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct SigningIdentity {
    pub identity_id: String,
    pub provider: String,
    pub slot_id: u64,
    pub token_label: Option<String>,
    pub token_model: Option<String>,
    pub token_serial: Option<String>,
    pub token_manufacturer: Option<String>,
    pub certificate_id: Option<String>,
    pub certificate_label: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub is_expired: bool,
    pub expires_soon: bool,
    pub is_default: bool,
    pub is_available: bool,
}

#[derive(Clone, Debug)]
pub struct ResolvedSigningIdentity {
    pub slot_id: u64,
    pub certificate_id: String,
    pub certificate_der_base64: Option<String>,
}
