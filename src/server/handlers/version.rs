use axum::Json;

use crate::{metadata, models::response::VersionResponse};

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: metadata::APP_NAME,
        version: metadata::APP_VERSION,
        build_date: metadata::BUILD_DATE,
        git_commit: metadata::GIT_COMMIT,
        release_channel: metadata::RELEASE_CHANNEL,
    })
}
