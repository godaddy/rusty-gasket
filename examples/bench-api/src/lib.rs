//! Shared types and router builder for bench-api benchmarks.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

/// Payload used for JSON serialization benchmarks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPayload {
    pub message: String,
    pub count: u64,
}

/// Empty 200 response — measures raw framework overhead.
pub async fn noop() -> StatusCode {
    StatusCode::OK
}

/// Small JSON response — measures serialization overhead.
pub async fn json_response() -> impl IntoResponse {
    Json(JsonPayload {
        message: "hello from rusty gasket".to_string(),
        count: 42,
    })
}

/// Echo JSON body — measures deserialization + serialization.
pub async fn json_echo(Json(body): Json<JsonPayload>) -> impl IntoResponse {
    Json(body)
}

/// Build a standalone benchmark router (used by criterion, no server needed).
pub fn build_bench_router() -> Router {
    Router::new()
        .route("/bench/noop", get(noop))
        .route("/bench/json", get(json_response))
        .route("/bench/echo", post(json_echo))
}
