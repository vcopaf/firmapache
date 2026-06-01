use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

use crate::models::compatible::{
    CompatibleOutputFile, CompatibleSignRequest, CompatibleSignResponse,
};
use crate::models::signing::SigningSessionFile;

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
    #[error("Invalid PDF input")]
    InvalidPdf,
    #[error("Unsupported sign format: {0}")]
    UnsupportedFormat(String),
}

#[derive(Debug)]
pub struct PreparedSignRequest {
    pub files: Vec<SigningSessionFile>,
    pub format: String,
    pub language: Option<String>,
}

pub fn prepare_sign_request(
    request: CompatibleSignRequest,
) -> Result<PreparedSignRequest, CompatibleSignError> {
    let CompatibleSignRequest {
        archivo,
        format,
        language: _language,
    } = request;

    let format = format.to_ascii_lowercase();
    if !matches!(format.as_str(), "jws" | "pdf") {
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
            if format == "pdf" && !is_valid_pdf_input(&contents) {
                return Err(CompatibleSignError::InvalidPdf);
            }
            Ok(SigningSessionFile {
                content_base64: STANDARD.encode(contents),
                name: file.name,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PreparedSignRequest {
        files,
        format,
        language: _language,
    })
}

fn is_valid_pdf_input(contents: &[u8]) -> bool {
    contents.starts_with(b"%PDF-")
        && contents
            .windows(b"%%EOF".len())
            .any(|window| window == b"%%EOF")
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

pub fn response_for_files(files: &[SigningSessionFile]) -> CompatibleSignResponse {
    CompatibleSignResponse {
        files: files
            .iter()
            .map(|file| CompatibleOutputFile {
                base64: file.content_base64.clone(),
                name: file.name.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::compatible::{CompatibleInputFile, CompatibleSignRequest};

    #[test]
    fn prepares_pdf_sign_request() {
        let request = CompatibleSignRequest {
            archivo: vec![CompatibleInputFile {
                base64: "data:application/pdf;base64,JVBERi0xLjcKJSB0ZXN0CiUlRU9GCg==".to_owned(),
                name: "documento.pdf".to_owned(),
            }],
            format: "pdf".to_owned(),
            language: Some("es".to_owned()),
        };

        let prepared = prepare_sign_request(request).expect("valid PDF payload");

        assert_eq!(prepared.format, "pdf");
        assert_eq!(prepared.files[0].name, "documento.pdf");
    }

    #[test]
    fn rejects_invalid_pdf_sign_request() {
        let request = CompatibleSignRequest {
            archivo: vec![CompatibleInputFile {
                base64: "aG9sYQ==".to_owned(),
                name: "documento.pdf".to_owned(),
            }],
            format: "pdf".to_owned(),
            language: None,
        };

        let error = prepare_sign_request(request).expect_err("invalid PDF must fail");

        assert!(matches!(error, CompatibleSignError::InvalidPdf));
    }
}
