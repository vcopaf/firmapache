use std::{fs, path::Path};

use serde::Serialize;

use super::error::PdfError;

#[derive(Clone, Debug, Serialize)]
pub struct PdfDocumentInfo {
    pub file_name: String,
    pub size_bytes: u64,
    pub valid_header: bool,
    pub has_eof_marker: bool,
}

pub fn inspect_pdf_file(path: impl AsRef<Path>) -> Result<PdfDocumentInfo, PdfError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(PdfError::EmptyPath);
    }

    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(PdfError::NotAFile);
    }

    let bytes = fs::read(path)?;
    Ok(inspect_pdf_bytes(
        file_name(path),
        metadata.len(),
        bytes.as_slice(),
    ))
}

pub fn inspect_pdf_bytes(file_name: String, size_bytes: u64, bytes: &[u8]) -> PdfDocumentInfo {
    PdfDocumentInfo {
        file_name,
        size_bytes,
        valid_header: bytes.starts_with(b"%PDF-"),
        has_eof_marker: bytes
            .windows(b"%%EOF".len())
            .any(|window| window == b"%%EOF"),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("documento.pdf")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_pdf_like_bytes() {
        let info = inspect_pdf_bytes("test.pdf".to_owned(), 17, b"%PDF-1.7\n%%EOF\n");

        assert_eq!(info.file_name, "test.pdf");
        assert_eq!(info.size_bytes, 17);
        assert!(info.valid_header);
        assert!(info.has_eof_marker);
    }

    #[test]
    fn flags_non_pdf_bytes() {
        let info = inspect_pdf_bytes("test.txt".to_owned(), 5, b"hello");

        assert!(!info.valid_header);
        assert!(!info.has_eof_marker);
    }
}
