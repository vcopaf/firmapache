use axum::{Json, extract::State};

use crate::{
    core::pkcs11::provider, error::AppError, models::pkcs11::CertificateInfo, server::AppState,
};

pub async fn certificates(
    State(state): State<AppState>,
) -> Result<Json<Vec<CertificateInfo>>, AppError> {
    let config = state.config()?;
    let certificates =
        tokio::task::spawn_blocking(move || provider::list_certificates(&config)).await??;

    Ok(Json(certificates))
}
