//! Structured error handling with standardized JSON responses.
//!
//! Provides the [`ApiError`] trait for application errors and the
//! `#[derive(ApiError)]` macro for ergonomic implementation.
//! All errors produce consistent JSON responses with correlation IDs
//! for support debugging.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

pub use rusty_gasket_macros::ApiError;

/// Trait that application error types implement for HTTP error responses.
///
/// Use `#[derive(ApiError)]` from `rusty_gasket_macros` for automatic
/// implementation, or implement manually for full control.
pub trait ApiError: std::error::Error + Send + Sync + 'static {
    /// Machine-readable error code (e.g., "`NOT_FOUND`", "`VALIDATION_ERROR`").
    fn error_code(&self) -> &str;

    /// HTTP status code for this error.
    fn status_code(&self) -> StatusCode;

    /// Whether to expose the error message to the client.
    /// Defaults to true for 4xx, false for 5xx (prevents internal details leaking).
    fn expose_details(&self) -> bool {
        self.status_code().is_client_error()
    }

    /// Structured sub-errors (e.g., per-field validation failures).
    fn details(&self) -> Vec<ErrorDetail> {
        Vec::new()
    }
}

/// Standardized JSON error response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ErrorResponse {
    /// Machine-readable error code (e.g., "`NOT_FOUND`", "`VALIDATION_ERROR`").
    pub error: String,
    /// Human-readable error message. For 5xx errors, this is a generic message
    /// with the correlation ID to prevent leaking internal details.
    pub message: String,
    /// Unique identifier for correlating this error with server-side logs.
    pub correlation_id: Uuid,
    /// Structured sub-errors (e.g., per-field validation failures). Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetail>,
}

/// RFC 9457 problem-details response body.
///
/// Rusty Gasket keeps [`ErrorResponse`] as the compact default error body for
/// backwards compatibility, but services that need standards-based error
/// responses can return `ProblemDetails` from handlers or middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProblemDetails {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Short, human-readable summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable detail for this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Extension members for application-specific fields.
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

impl ProblemDetails {
    /// Create a problem-details response body with a stable problem type.
    #[must_use]
    pub fn new(
        status: StatusCode,
        problem_type: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            problem_type: problem_type.into(),
            title: title.into(),
            status: status.as_u16(),
            detail: None,
            instance: None,
            extensions: Map::new(),
        }
    }

    /// Add occurrence-specific detail text.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add an instance URI for this specific error occurrence.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    /// Add a JSON extension member.
    #[must_use]
    pub fn with_extension(mut self, name: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(name.into(), value);
        self
    }
}

impl ErrorResponse {
    /// Create a new error response.
    #[must_use]
    pub fn new(error: impl Into<String>, message: impl Into<String>, correlation_id: Uuid) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            correlation_id,
            details: Vec::new(),
        }
    }

    /// Create a new error response with details.
    #[must_use]
    pub fn with_details(
        error: impl Into<String>,
        message: impl Into<String>,
        correlation_id: Uuid,
        details: Vec<ErrorDetail>,
    ) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            correlation_id,
            details,
        }
    }
}

/// A single sub-error within an [`ErrorResponse`] (e.g., one field validation failure).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorDetail {
    /// Short identifier for the issue (e.g., a field name or constraint name).
    pub issue: String,
    /// Longer description of the problem, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ErrorDetail {
    /// Create a new error detail with just an issue identifier.
    #[must_use]
    pub fn new(issue: impl Into<String>) -> Self {
        Self {
            issue: issue.into(),
            description: None,
        }
    }

    /// Create a new error detail with an issue identifier and description.
    #[must_use]
    pub fn with_description(issue: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            issue: issue.into(),
            description: Some(description.into()),
        }
    }
}

/// Walk the full error source chain into a single string for internal logging.
pub fn full_error_chain(error: &dyn std::error::Error) -> String {
    let mut msg = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        msg.push_str(" | caused by: ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}

/// Retrieve the current request's correlation ID, or generate a new one.
fn correlation_id() -> Uuid {
    crate::observability::current_request_id()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::now_v7)
}

/// Attach the correlation ID as both a JSON field and a response header.
fn finalize_error_response(status: StatusCode, body: ErrorResponse) -> Response {
    let cid = body.correlation_id;
    let mut response = (status, axum::Json(body)).into_response();
    if let Ok(val) = http::HeaderValue::from_str(&cid.to_string()) {
        response.headers_mut().insert("X-Correlation-ID", val);
    }
    response
}

/// Convert an `ApiError` into an axum `Response` with standardized JSON body.
/// Called by the `IntoResponse` implementation generated by `#[derive(ApiError)]`.
pub fn error_into_response(error: &impl ApiError) -> Response {
    let cid = correlation_id();
    let status = error.status_code();

    let (message, details) = if error.expose_details() {
        (error.to_string(), error.details())
    } else {
        // The correlation_id is already returned in the JSON body's
        // `correlationId` field and the `X-Correlation-ID` response
        // header, so the message itself stays generic.
        ("Internal server error".to_string(), Vec::new())
    };

    if status.is_server_error() {
        tracing::error!(
            error_code = error.error_code(),
            status = status.as_u16(),
            correlation_id = %cid,
            error_chain = %full_error_chain(error),
            "Server error"
        );
    } else {
        tracing::warn!(
            error_code = error.error_code(),
            status = status.as_u16(),
            correlation_id = %cid,
            error_chain = %full_error_chain(error),
            "Client error"
        );
    }

    let body = ErrorResponse::with_details(error.error_code(), message, cid, details);
    finalize_error_response(status, body)
}

/// Build a standardized JSON error response with correlation ID and header.
#[must_use]
pub fn quick_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = ErrorResponse::new(code, message, correlation_id());
    finalize_error_response(status, body)
}

/// Build a standardized JSON error response that includes structured details.
#[must_use]
pub fn quick_error_response_with_details(
    status: StatusCode,
    code: &str,
    message: &str,
    details: Vec<ErrorDetail>,
) -> Response {
    let body = ErrorResponse::with_details(code, message, correlation_id(), details);
    finalize_error_response(status, body)
}

/// Build an RFC 9457 problem-details JSON response.
#[must_use]
pub fn problem_response(status: StatusCode, problem: ProblemDetails) -> Response {
    let mut response = (status, axum::Json(problem)).into_response();
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/problem+json"),
    );
    response
}

/// Built-in errors for framework-level failures (404, 405, 500).
///
/// Implementation dogfoods the `#[derive(ApiError)]` macro so the
/// framework's own errors exercise the same code path consumer
/// errors do. `Internal` uses `expose = false` so the wrapped error's
/// message is redacted from the 500 response body — the correlation
/// id in the JSON `correlationId` field and the `X-Correlation-ID`
/// response header lets operators find the full chain in logs.
#[derive(Debug, thiserror::Error, rusty_gasket_macros::ApiError)]
#[non_exhaustive]
pub enum FrameworkError {
    #[error("Not found")]
    #[api_error(code = "NOT_FOUND", status = 404)]
    NotFound,

    #[error("Method not allowed")]
    #[api_error(code = "METHOD_NOT_ALLOWED", status = 405)]
    MethodNotAllowed,

    #[error("Internal server error")]
    #[api_error(code = "INTERNAL_ERROR", status = 500, expose = false)]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Debug, thiserror::Error, ApiError)]
    enum TestError {
        #[error("thing not found: {0}")]
        #[api_error(code = "NOT_FOUND", status = 404)]
        NotFound(String),

        #[error("bad input")]
        #[api_error(code = "BAD_REQUEST", status = 400)]
        BadRequest,

        #[error("kaboom")]
        #[api_error(code = "INTERNAL", status = 500, expose = false)]
        Internal,

        #[error("custom exposed 500")]
        #[api_error(code = "CUSTOM_500", status = 500, expose = true)]
        CustomExposed,

        #[error("validation failed")]
        #[api_error(code = "VALIDATION", status = 422)]
        Validation { _field: String },
    }

    #[test]
    fn derived_error_code_and_status() {
        let e = TestError::NotFound("x".into());
        assert_eq!(e.error_code(), "NOT_FOUND");
        assert_eq!(e.status_code(), StatusCode::NOT_FOUND);
        assert!(e.expose_details());
    }

    #[test]
    fn derived_500_hides_by_default() {
        let e = TestError::Internal;
        assert_eq!(e.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!e.expose_details());
    }

    #[test]
    fn derived_500_with_explicit_expose() {
        let e = TestError::CustomExposed;
        assert_eq!(e.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(e.expose_details());
    }

    #[test]
    fn derived_unit_variant() {
        let e = TestError::BadRequest;
        assert_eq!(e.error_code(), "BAD_REQUEST");
        assert_eq!(e.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn derived_struct_variant() {
        let e = TestError::Validation {
            _field: "email".into(),
        };
        assert_eq!(e.error_code(), "VALIDATION");
        assert_eq!(e.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
