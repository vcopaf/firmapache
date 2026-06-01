use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PdfError {
    #[error("PDF path is empty")]
    EmptyPath,
    #[error("could not read PDF file: {0}")]
    Read(#[from] io::Error),
    #[error("selected path is not a file")]
    NotAFile,
}
