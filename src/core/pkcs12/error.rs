use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Pkcs12Error {
    #[error("PKCS#12 token not found")]
    TokenNotFound,
    #[error("PKCS#12 path does not exist: {0}")]
    PathNotFound(String),
    #[error("PKCS#12 password environment variable not found")]
    PasswordEnvironmentVariableNotFound,
    #[error("could not read PKCS#12 file: {0}")]
    Read(#[from] io::Error),
    #[error("could not parse PKCS#12 file")]
    Parse,
    #[error("PKCS#12 certificate not found")]
    CertificateNotFound,
    #[error("PKCS#12 private key not found")]
    PrivateKeyNotFound,
    #[error("PKCS#12 signing failed")]
    SigningFailed,
    #[error("PKCS#12 generation failed")]
    GenerationFailed,
    #[error("PKCS#12 output file already exists: {0}")]
    OutputAlreadyExists(String),
}
