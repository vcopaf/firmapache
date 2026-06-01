use std::io;

use thiserror::Error;

use crate::{
    core::signing::jws::JwsSignError,
    core::{cache::CacheError, pkcs11::provider::ProviderError},
};

#[derive(Debug, Error)]
pub enum PdfError {
    #[error("PDF path is empty")]
    EmptyPath,
    #[error("could not read PDF file: {0}")]
    Read(#[from] io::Error),
    #[error("could not write signed PDF file: {0}")]
    Write(io::Error),
    #[error("selected path is not a file")]
    NotAFile,
    #[error("selected file is not a valid PDF")]
    InvalidPdf,
    #[error("could not manipulate PDF structure: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("certificate not found")]
    CertificateNotFound,
    #[error("certificate DER is not valid base64")]
    InvalidCertificateBase64,
    #[error("could not parse signing certificate")]
    InvalidCertificate,
    #[error("CMS signature is larger than reserved PDF space: {actual} > {reserved}")]
    CmsTooLarge { actual: usize, reserved: usize },
    #[error("PDF signature placeholder not found: {0}")]
    PlaceholderNotFound(&'static str),
    #[error(transparent)]
    Pkcs11(#[from] ProviderError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error(transparent)]
    Jws(#[from] JwsSignError),
}
