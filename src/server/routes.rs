use anyhow::Result;
use axum::{
    Router,
    http::Method,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use super::AppState;
use super::handlers::{
    certificates::certificates,
    compatible_sign::compatible_sign,
    config::{get_config, update_config},
    home::home,
    pkcs11::{library, tokens},
    sign::sign_hash,
    signing_sessions::{approve, reject, session, sessions},
    status::status,
    verify::verify_hash,
    version::version,
};
use crate::error::AppError;

pub fn router(state: AppState) -> Result<Router> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    Ok(Router::new()
        .route("/", get(home))
        .route("/status", get(status))
        .route("/version", get(version))
        .route("/pkcs11/library", get(library))
        .route("/tokens", get(tokens))
        .route("/certificates", get(certificates))
        .route("/sign", post(compatible_sign))
        .route("/sign/sessions", get(sessions))
        .route("/sign/sessions/{id}", get(session))
        .route("/sign/sessions/{id}/approve", post(approve))
        .route("/sign/sessions/{id}/reject", post(reject))
        .route("/sign/hash", post(sign_hash))
        .route("/verify/hash", post(verify_hash))
        .route("/config", get(get_config).post(update_config))
        .fallback(not_found)
        .layer(cors)
        .with_state(state))
}

async fn not_found() -> AppError {
    AppError::NotFound
}
