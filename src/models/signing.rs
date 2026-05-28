use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::compatible::CompatibleSignResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningSessionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningSession {
    pub id: Uuid,
    pub files: Vec<SigningSessionFile>,
    pub format: String,
    pub language: Option<String>,
    pub status: SigningSessionStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningSessionFile {
    pub name: String,
    pub content_base64: String,
}

#[derive(Debug, Clone)]
pub struct ApproveSigningSessionInput {
    pub slot_id: u64,
    pub certificate_id: String,
    pub pin: String,
}

pub enum SigningSessionResult {
    Signed(CompatibleSignResponse),
    Rejected,
    Expired,
}
