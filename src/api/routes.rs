use axum::{
    Router,
    routing::{get, post},
};

use super::handlers::{
    certificates::certificates,
    pkcs11::{library, tokens},
    sign::sign_hash,
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
        .route("/sign/hash", post(sign_hash))
        .fallback(not_found)
}

async fn not_found() -> AppError {
    AppError::NotFound
}
