use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct CompatibleSignRequest {
    pub archivo: Vec<CompatibleInputFile>,
    pub format: String,
    pub language: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompatibleInputFile {
    pub base64: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatibleSignResponse {
    pub files: Vec<CompatibleOutputFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatibleOutputFile {
    pub base64: String,
    pub name: String,
}
