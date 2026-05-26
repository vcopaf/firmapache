use axum::{Json, extract::State};

use crate::{
    config::{AppConfig, AppConfigUpdate},
    error::AppError,
    server::AppState,
};

pub async fn get_config(State(state): State<AppState>) -> Result<Json<AppConfig>, AppError> {
    Ok(Json(state.config()?))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(update): Json<AppConfigUpdate>,
) -> Result<Json<AppConfig>, AppError> {
    let config = state.config()?.apply_update(update)?;
    config.save()?;
    state.replace_config(config.clone())?;

    Ok(Json(config))
}
