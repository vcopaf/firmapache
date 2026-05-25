use axum::{Router, routing::get};

use super::handlers::{
    certificates::certificates,
    pkcs11::{library, tokens},
    status::status,
    version::version,
};
use crate::error::AppError;

pub fn router() -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/version", get(version))
        .route("/pkcs11/library", get(library))
        .route("/tokens", get(tokens))
        .route("/certificates", get(certificates))
        .fallback(not_found)
}

async fn not_found() -> AppError {
    AppError::NotFound
}
