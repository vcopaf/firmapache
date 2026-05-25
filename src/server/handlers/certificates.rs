use axum::Json;

use crate::{core::pkcs11::provider, error::AppError, models::pkcs11::CertificateInfo};

pub async fn certificates() -> Result<Json<Vec<CertificateInfo>>, AppError> {
    let certificates = tokio::task::spawn_blocking(provider::list_certificates).await??;

    Ok(Json(certificates))
}
