use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CompatibleSignRequest {
    pub archivo: Vec<CompatibleInputFile>,
    pub format: String,
    pub language: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompatibleInputFile {
    pub base64: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CompatibleSignResponse {
    pub files: Vec<CompatibleOutputFile>,
}

#[derive(Debug, Serialize)]
pub struct CompatibleOutputFile {
    pub base64: String,
    pub name: String,
}
