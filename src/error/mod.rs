use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("route not found")]
    NotFound,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    message: &'static str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::warn!(error = %self, "request rejected");

        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found",
                message: "route not found",
            }),
        )
            .into_response()
    }
}
