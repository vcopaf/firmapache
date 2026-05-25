use axum::{Router, routing::get};

use super::handlers::{status::status, version::version};
use crate::error::AppError;

pub fn router() -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/version", get(version))
        .fallback(not_found)
}

async fn not_found() -> AppError {
    AppError::NotFound
}
