use axum::{Json, extract::State};

use crate::{
    core::pkcs11::provider,
    error::AppError,
    models::pkcs11::{SignHashRequest, SignHashResponse},
    server::AppState,
};

pub async fn sign_hash(
    State(state): State<AppState>,
    Json(request): Json<SignHashRequest>,
) -> Result<Json<SignHashResponse>, AppError> {
    let config = state.config()?;
    let response =
        tokio::task::spawn_blocking(move || provider::sign_hash(&config, request)).await??;

    Ok(Json(response))
}
