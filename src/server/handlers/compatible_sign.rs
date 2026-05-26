use axum::Json;

use crate::{
    core::signing::compatible,
    error::AppError,
    models::compatible::{CompatibleSignRequest, CompatibleSignResponse},
};

pub async fn compatible_sign(
    Json(request): Json<CompatibleSignRequest>,
) -> Result<Json<CompatibleSignResponse>, AppError> {
    Ok(Json(compatible::prepare_sign_request(request)?))
}
