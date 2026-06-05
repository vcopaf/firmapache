use axum::{Json, extract::State};

use crate::{
    core::{
        development::{self, DevelopmentAutoSign},
        signing::session_manager::SigningSessionError,
    },
    error::AppError,
    models::compatible::{CompatibleSignRequest, CompatibleSignResponse},
    models::signing::SigningSessionResult,
    server::AppState,
};

pub async fn compatible_sign(
    State(state): State<AppState>,
    Json(request): Json<CompatibleSignRequest>,
) -> Result<Json<CompatibleSignResponse>, AppError> {
    let auto_sign_request = request.clone();
    let config = state.config()?;
    let cache = state.token_certificate_cache().clone();
    match tokio::task::spawn_blocking(move || {
        development::try_auto_sign(&config, &cache, auto_sign_request)
    })
    .await??
    {
        DevelopmentAutoSign::Signed(response) => return Ok(Json(response)),
        DevelopmentAutoSign::Fallback(reason) => {
            tracing::warn!(%reason, "continuing with interactive signing flow");
        }
        DevelopmentAutoSign::NotEnabled => {}
    }

    match state.signing_sessions().create_and_wait(request).await? {
        SigningSessionResult::Signed(response) => Ok(Json(response)),
        SigningSessionResult::Rejected => Err(SigningSessionError::Rejected.into()),
        SigningSessionResult::Expired => Err(SigningSessionError::Expired.into()),
    }
}
