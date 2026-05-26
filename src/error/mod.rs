use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::{
    config::ConfigError,
    core::{
        crypto::verifier::VerifyError, pkcs11::provider::ProviderError,
        signing::compatible::CompatibleSignError,
    },
};

#[derive(Debug, Error)]
pub enum AppError {
    #[error("route not found")]
    NotFound,
    #[error(transparent)]
    Pkcs11(#[from] ProviderError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    CompatibleSign(#[from] CompatibleSignError),
    #[error("PKCS#11 task failed: {0}")]
    Pkcs11Task(#[from] tokio::task::JoinError),
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "route not found".to_owned()),
            Self::Pkcs11(ProviderError::LibraryNotFound) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "PKCS#11 library not found".to_owned(),
            ),
            Self::Pkcs11(ProviderError::InvalidEnvironmentPath(path)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("MINI_FIRMADOR_PKCS11 path does not exist: {path}"),
            ),
            Self::Pkcs11(ProviderError::LoginFailed) => (
                StatusCode::UNAUTHORIZED,
                "PKCS#11 login failed. Check PIN. No retry was attempted.".to_owned(),
            ),
            Self::Pkcs11(ProviderError::InvalidBase64Hash) => (
                StatusCode::BAD_REQUEST,
                "hash_base64 is not valid base64".to_owned(),
            ),
            Self::Pkcs11(ProviderError::InvalidCertificateId) => (
                StatusCode::BAD_REQUEST,
                "certificate_id must be a non-empty hexadecimal string".to_owned(),
            ),
            Self::Pkcs11(ProviderError::UnsupportedMechanism(mechanism)) => (
                StatusCode::BAD_REQUEST,
                format!("unsupported signing mechanism: {mechanism}"),
            ),
            Self::Pkcs11(ProviderError::SlotNotFound(slot_id)) => (
                StatusCode::NOT_FOUND,
                format!("PKCS#11 slot not found or has no token: {slot_id}"),
            ),
            Self::Pkcs11(ProviderError::PrivateKeyNotFound) => (
                StatusCode::NOT_FOUND,
                "PKCS#11 private key not found".to_owned(),
            ),
            Self::Pkcs11(ProviderError::PrivateKeyNotFoundForCertificate) => (
                StatusCode::NOT_FOUND,
                "Private key not found for selected certificate_id".to_owned(),
            ),
            Self::Verify(VerifyError::UnsupportedMechanism(mechanism)) => (
                StatusCode::BAD_REQUEST,
                format!("unsupported verification mechanism: {mechanism}"),
            ),
            Self::Verify(error) => (StatusCode::BAD_REQUEST, error.to_string()),
            Self::Config(ConfigError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, message.to_owned())
            }
            Self::Config(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration operation failed".to_owned(),
            ),
            Self::CompatibleSign(error) => (StatusCode::BAD_REQUEST, error.to_string()),
            Self::Pkcs11(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "PKCS#11 operation failed".to_owned(),
            ),
            Self::Pkcs11Task(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "PKCS#11 operation failed".to_owned(),
            ),
        };

        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::warn!(error = %self, "request rejected");
        }

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}
