use axum::{
    Json,
    extract::{Path, State},
};
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{compatible::CompatibleSignResponse, signing::SigningSession},
    server::AppState,
};

pub async fn sessions(
    State(state): State<AppState>,
) -> Result<Json<Vec<SigningSession>>, AppError> {
    Ok(Json(state.signing_sessions().list()?))
}

pub async fn session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SigningSession>, AppError> {
    Ok(Json(state.signing_sessions().get(id)?))
}

pub async fn approve(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CompatibleSignResponse>, AppError> {
    Ok(Json(state.signing_sessions().approve_temporarily(id)?))
}

pub async fn reject(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SigningSession>, AppError> {
    Ok(Json(state.signing_sessions().reject(id)?))
}
