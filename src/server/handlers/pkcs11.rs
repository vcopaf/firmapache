use axum::{Json, extract::State};

use crate::{
    core::pkcs11::provider,
    error::AppError,
    models::pkcs11::{Pkcs11LibraryInfo, TokenInfo},
    server::AppState,
};

pub async fn library(State(state): State<AppState>) -> Result<Json<Pkcs11LibraryInfo>, AppError> {
    Ok(Json(provider::detect_pkcs11_library(&state.config()?)?))
}

pub async fn tokens(State(state): State<AppState>) -> Result<Json<Vec<TokenInfo>>, AppError> {
    let config = state.config()?;
    let cache = state.token_certificate_cache().clone();
    let tokens = if cache.snapshot()?.loaded_at.is_some() {
        cache.get_cached_tokens()?
    } else {
        tokio::task::spawn_blocking(move || cache.refresh_fast(&config))
            .await??
            .tokens
    };

    Ok(Json(tokens))
}
