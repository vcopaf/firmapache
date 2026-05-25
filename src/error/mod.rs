use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::pkcs11::provider::ProviderError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("route not found")]
    NotFound,
    #[error(transparent)]
    Pkcs11(#[from] ProviderError),
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
