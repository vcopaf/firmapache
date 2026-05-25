use axum::Json;

use crate::{error::AppError, models::pkcs11::CertificateInfo, pkcs11::provider};

pub async fn certificates() -> Result<Json<Vec<CertificateInfo>>, AppError> {
    let certificates = tokio::task::spawn_blocking(provider::list_certificates).await??;

    Ok(Json(certificates))
}
