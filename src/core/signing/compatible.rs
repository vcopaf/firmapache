use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

use crate::models::compatible::{
    CompatibleOutputFile, CompatibleSignRequest, CompatibleSignResponse,
};

#[derive(Debug, Error)]
pub enum CompatibleSignError {
    #[error("archivo must not be empty")]
    EmptyFiles,
    #[error("File name must not be empty")]
    EmptyName,
    #[error("File base64 must not be empty")]
    EmptyBase64,
    #[error("Invalid base64 input")]
    InvalidBase64,
    #[error("Unsupported sign format: {0}")]
    UnsupportedFormat(String),
}

pub fn prepare_sign_request(
    request: CompatibleSignRequest,
) -> Result<CompatibleSignResponse, CompatibleSignError> {
    let CompatibleSignRequest {
        archivo,
        format,
        language: _language,
    } = request;

    if format != "jws" {
        return Err(CompatibleSignError::UnsupportedFormat(format));
    }
    if archivo.is_empty() {
        return Err(CompatibleSignError::EmptyFiles);
    }

    let files = archivo
        .into_iter()
        .map(|file| {
            if file.name.trim().is_empty() {
                return Err(CompatibleSignError::EmptyName);
            }

            let contents = parse_input_base64(&file.base64)?;
            Ok(CompatibleOutputFile {
                base64: STANDARD.encode(contents),
                name: file.name,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompatibleSignResponse { files })
}

pub fn parse_input_base64(input: &str) -> Result<Vec<u8>, CompatibleSignError> {
    if input.trim().is_empty() {
        return Err(CompatibleSignError::EmptyBase64);
    }

    let encoded = if input.starts_with("data:") {
        input
            .split_once(',')
            .map(|(_, encoded)| encoded)
            .ok_or(CompatibleSignError::InvalidBase64)?
    } else {
        input
    };

    if encoded.is_empty() {
        return Err(CompatibleSignError::EmptyBase64);
    }

    STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| CompatibleSignError::InvalidBase64)
}
