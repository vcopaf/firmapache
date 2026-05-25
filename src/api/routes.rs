use axum::{Router, routing::get};

use super::handlers::{
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
        .fallback(not_found)
}

async fn not_found() -> AppError {
    AppError::NotFound
}
