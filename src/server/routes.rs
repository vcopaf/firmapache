use anyhow::{Context, Result};
use axum::{
    Router,
    http::{HeaderValue, Method, header::CONTENT_TYPE},
    routing::{get, post},
};
use tower_http::cors::CorsLayer;

use super::AppState;
use super::handlers::{
    certificates::certificates,
    config::{get_config, update_config},
    pkcs11::{library, tokens},
    sign::sign_hash,
    status::status,
    verify::verify_hash,
    version::version,
};
use crate::{config::AppConfig, error::AppError};

pub fn router(config: AppConfig) -> Result<Router> {
    let allowed_origins = config
        .cors
        .allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .with_context(|| format!("invalid CORS allowed origin: {origin}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE]);
    let state = AppState::new(config);

    Ok(Router::new()
        .route("/status", get(status))
        .route("/version", get(version))
        .route("/pkcs11/library", get(library))
        .route("/tokens", get(tokens))
        .route("/certificates", get(certificates))
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
