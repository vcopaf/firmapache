use axum::{Json, extract::State};

use crate::{
    core::signing::session_manager::SigningSessionError,
    error::AppError,
    models::compatible::{CompatibleSignRequest, CompatibleSignResponse},
    models::signing::SigningSessionResult,
    server::AppState,
};

pub async fn compatible_sign(
    State(state): State<AppState>,
    Json(request): Json<CompatibleSignRequest>,
) -> Result<Json<CompatibleSignResponse>, AppError> {
    match state.signing_sessions().create_and_wait(request).await? {
        SigningSessionResult::Signed(response) => Ok(Json(response)),
        SigningSessionResult::Rejected => Err(SigningSessionError::Rejected.into()),
        SigningSessionResult::Expired => Err(SigningSessionError::Expired.into()),
    }
}
