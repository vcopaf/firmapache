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
    let tokens = tokio::task::spawn_blocking(move || provider::list_tokens(&config)).await??;

    Ok(Json(tokens))
}
