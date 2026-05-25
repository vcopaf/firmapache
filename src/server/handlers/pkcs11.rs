use axum::Json;

use crate::{
    core::pkcs11::provider,
    error::AppError,
    models::pkcs11::{Pkcs11LibraryInfo, TokenInfo},
};

pub async fn library() -> Result<Json<Pkcs11LibraryInfo>, AppError> {
    Ok(Json(provider::detect_pkcs11_library()?))
}

pub async fn tokens() -> Result<Json<Vec<TokenInfo>>, AppError> {
    let tokens = tokio::task::spawn_blocking(provider::list_tokens).await??;

    Ok(Json(tokens))
}
