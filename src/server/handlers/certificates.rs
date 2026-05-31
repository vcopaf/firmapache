use axum::{Json, extract::State};

use crate::{error::AppError, models::pkcs11::CertificateInfo, server::AppState};

pub async fn certificates(
    State(state): State<AppState>,
) -> Result<Json<Vec<CertificateInfo>>, AppError> {
    let config = state.config()?;
    let cache = state.token_certificate_cache().clone();
    let certificates = if cache.snapshot()?.loaded_at.is_some() {
        cache.get_cached_certificates()?
    } else {
        tokio::task::spawn_blocking(move || cache.refresh_tokens_and_certificates(&config))
            .await??
            .certificates
    };

    Ok(Json(certificates))
}
