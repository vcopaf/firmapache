use axum::Json;

use crate::{
    core::pkcs11::provider,
    error::AppError,
    models::pkcs11::{SignHashRequest, SignHashResponse},
};

pub async fn sign_hash(
    Json(request): Json<SignHashRequest>,
) -> Result<Json<SignHashResponse>, AppError> {
    let response = tokio::task::spawn_blocking(move || provider::sign_hash(request)).await??;

    Ok(Json(response))
}
