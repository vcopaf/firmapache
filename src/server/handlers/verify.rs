use axum::Json;

use crate::{
    core::crypto::verifier,
    error::AppError,
    models::pkcs11::{VerifyHashRequest, VerifyHashResponse},
};

pub async fn verify_hash(
    Json(request): Json<VerifyHashRequest>,
) -> Result<Json<VerifyHashResponse>, AppError> {
    let response = tokio::task::spawn_blocking(move || verifier::verify_hash(request)).await??;

    Ok(Json(response))
}
