use axum::Json;

use crate::models::response::StatusResponse;

pub async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok",
        service: env!("CARGO_PKG_NAME"),
    })
}
