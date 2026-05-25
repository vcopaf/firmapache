use axum::Json;

use crate::{
    error::AppError,
    models::pkcs11::{SignHashRequest, SignHashResponse},
    pkcs11::provider,
};

pub async fn sign_hash(
    Json(request): Json<SignHashRequest>,
) -> Result<Json<SignHashResponse>, AppError> {
    let response = tokio::task::spawn_blocking(move || provider::sign_hash(request)).await??;

    Ok(Json(response))
}
