//! Novice-friendly request extractors for API handlers.
//!
//! These wrappers sit on top of axum's extractors and keep generated API code
//! readable. Handlers can ask for domain concepts such as [`JsonBody`],
//! [`QueryParams`], [`PathParams`], [`Pagination`], [`RequestContext`], and
//! [`Context`] instead of spelling lower-level axum plumbing in every route.

use std::ops::Deref;
use std::time::Duration;

use axum::Json;
use axum::extract::{FromRef, FromRequest, FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::ErrorDetail;
use crate::observability::{RequestId, X_REQUEST_ID};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;
const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 255;

/// JSON request body extractor with Rusty Gasket's standard error shape.
///
/// Use this instead of `axum::Json<T>` in generated handlers when you want
/// invalid JSON and deserialization failures to return the framework's
/// consistent JSON error body with a correlation ID.
#[derive(Debug, Clone)]
pub struct JsonBody<T>(pub T);

impl<T> JsonBody<T> {
    /// Consume the extractor and return the parsed body.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for JsonBody<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| {
                standard_bad_request("INVALID_JSON", "Request body is not valid JSON.", rejection)
            })
    }
}

/// Query-string extractor with Rusty Gasket's standard error shape.
#[derive(Debug, Clone)]
pub struct QueryParams<T>(pub T);

impl<T> QueryParams<T> {
    /// Consume the extractor and return the parsed query parameters.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for QueryParams<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequestParts<S> for QueryParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection| {
                standard_bad_request("INVALID_QUERY", "Query parameters are invalid.", rejection)
            })
    }
}

/// Path-parameter extractor with Rusty Gasket's standard error shape.
#[derive(Debug, Clone)]
pub struct PathParams<T>(pub T);

impl<T> PathParams<T> {
    /// Consume the extractor and return the parsed path parameters.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for PathParams<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequestParts<S> for PathParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection| {
                standard_bad_request("INVALID_PATH", "Path parameters are invalid.", rejection)
            })
    }
}

/// Idempotency key supplied by callers for retry-safe mutation endpoints.
///
/// This extractor standardizes the `Idempotency-Key` header validation and
/// error response. It does not store responses by itself; applications can use
/// the extracted key with their database, cache, or job table so replay behavior
/// is explicit and durable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Borrow the validated idempotency key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the extractor and return the owned key.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl<S> FromRequestParts<S> for IdempotencyKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get("idempotency-key")
            .ok_or_else(missing_idempotency_key_response)?
            .to_str()
            .map_err(|_| invalid_idempotency_key_response())?
            .trim();

        if key.is_empty()
            || key.len() > MAX_IDEMPOTENCY_KEY_LENGTH
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid_idempotency_key_response());
        }

        Ok(Self(key.to_owned()))
    }
}

/// Validation contract for request types.
///
/// Implement this on request DTOs and use [`Validated<T>`] in handlers to parse
/// and validate JSON in one readable step.
pub trait Validate {
    /// Validate the parsed request value.
    ///
    /// # Errors
    /// Returns validation errors that should be sent to the caller as a 400
    /// response.
    fn validate(&self) -> Result<(), ValidationErrors>;
}

/// A single validation error for generated API request types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Field or logical constraint that failed.
    pub field: String,
    /// Human-readable validation message.
    pub message: String,
}

impl ValidationError {
    /// Create a validation error for a field.
    #[must_use]
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Collection of validation errors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationErrors {
    errors: Vec<ValidationError>,
}

impl ValidationErrors {
    /// Create an empty validation error collection.
    #[must_use]
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Create a collection with one validation error.
    #[must_use]
    pub fn one(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            errors: vec![ValidationError::new(field, message)],
        }
    }

    /// Add another validation error.
    pub fn push(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationError::new(field, message));
    }

    /// Whether no validation errors are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Borrow the collected validation errors.
    #[must_use]
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    fn into_error_details(self) -> Vec<ErrorDetail> {
        self.errors
            .into_iter()
            .map(|error| ErrorDetail::with_description(error.field, error.message))
            .collect()
    }
}

/// JSON body extractor that runs request validation before the handler starts.
#[derive(Debug, Clone)]
pub struct Validated<T>(pub T);

impl<T> Validated<T> {
    /// Consume the extractor and return the validated request value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Validated<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequest<S> for Validated<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Validate,
{
    type Rejection = Response;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let body = JsonBody::<T>::from_request(request, state).await?;
        body.validate().map_err(validation_error_response)?;
        Ok(Self(body.into_inner()))
    }
}

/// Standard pagination query parameters.
///
/// Accepts `?page=1&limit=50`. Missing values default to page 1 and a limit of
/// 50. Limits above 500 are capped to protect services from accidental large
/// responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pagination {
    page: usize,
    limit: usize,
}

impl Pagination {
    /// Current 1-based page number.
    #[must_use]
    pub const fn page(&self) -> usize {
        self.page
    }

    /// Maximum number of items requested.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Zero-based offset for SQL-style pagination.
    #[must_use]
    pub const fn offset(&self) -> usize {
        (self.page - 1) * self.limit
    }
}

#[derive(Debug, serde::Deserialize)]
struct RawPagination {
    page: Option<usize>,
    limit: Option<usize>,
}

impl<S> FromRequestParts<S> for Pagination
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let query = QueryParams::<RawPagination>::from_request_parts(parts, state).await?;
        let page = query.page.unwrap_or(1);
        if page == 0 {
            return Err(validation_error_response(ValidationErrors::one(
                "page",
                "page must be at least 1",
            )));
        }

        let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
        if limit == 0 {
            return Err(validation_error_response(ValidationErrors::one(
                "limit",
                "limit must be at least 1",
            )));
        }

        Ok(Self { page, limit })
    }
}

/// Request metadata commonly needed by handlers and logs.
#[derive(Debug, Clone)]
pub struct RequestContext {
    method: http::Method,
    uri: http::Uri,
    request_id: Option<String>,
}

impl RequestContext {
    /// HTTP method for the current request.
    #[must_use]
    pub const fn method(&self) -> &http::Method {
        &self.method
    }

    /// Request URI.
    #[must_use]
    pub const fn uri(&self) -> &http::Uri {
        &self.uri
    }

    /// Correlation/request ID generated or propagated by the logging middleware.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl<S> FromRequestParts<S> for RequestContext
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .map(|request_id| request_id.as_str().to_owned())
            .or_else(|| {
                parts
                    .headers
                    .get(X_REQUEST_ID)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            });

        Ok(Self {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            request_id,
        })
    }
}

/// Friendly wrapper around axum state extraction.
///
/// Generated handlers can ask for `Context<AppServices>` instead of
/// `State<AppServices>`, making the function signature read like application
/// code while still using axum's proven state extraction underneath.
#[derive(Debug, Clone)]
pub struct Context<T>(pub T);

impl<T> Context<T> {
    /// Consume the extractor and return the inner application context.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Context<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequestParts<S> for Context<T>
where
    S: Send + Sync,
    T: FromRef<S> + Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        State::<T>::from_request_parts(parts, state)
            .await
            .map(|State(value)| Self(value))
            .map_err(|_| {
                crate::error::quick_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CONTEXT_NOT_AVAILABLE",
                    "Application context is not available for this route.",
                )
            })
    }
}

/// Duration helper for configuring middleware from seconds.
#[must_use]
pub const fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn standard_bad_request(code: &str, message: &str, _rejection: impl IntoResponse) -> Response {
    tracing::debug!(
        status = StatusCode::BAD_REQUEST.as_u16(),
        "Request extraction failed"
    );
    crate::error::quick_error_response(StatusCode::BAD_REQUEST, code, message)
}

fn validation_error_response(errors: ValidationErrors) -> Response {
    crate::error::quick_error_response_with_details(
        StatusCode::BAD_REQUEST,
        "VALIDATION_ERROR",
        "Request validation failed.",
        errors.into_error_details(),
    )
}

fn missing_idempotency_key_response() -> Response {
    crate::error::quick_error_response(
        StatusCode::BAD_REQUEST,
        "IDEMPOTENCY_KEY_REQUIRED",
        "Idempotency-Key header is required for this endpoint.",
    )
}

fn invalid_idempotency_key_response() -> Response {
    crate::error::quick_error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_IDEMPOTENCY_KEY",
        "Idempotency-Key header must be visible ASCII text between 1 and 255 characters.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::{get, post};
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};
    use tower::ServiceExt;

    #[derive(Debug, Deserialize, Serialize)]
    struct CreateThing {
        name: String,
    }

    impl Validate for CreateThing {
        fn validate(&self) -> Result<(), ValidationErrors> {
            if self.name.trim().is_empty() {
                return Err(ValidationErrors::one("name", "name is required"));
            }
            Ok(())
        }
    }

    async fn create_thing(Validated(body): Validated<CreateThing>) -> Json<CreateThing> {
        Json(body)
    }

    async fn read_pagination(pagination: Pagination) -> Json<Pagination> {
        Json(pagination)
    }

    async fn read_idempotency_key(idempotency_key: IdempotencyKey) -> String {
        idempotency_key.into_string()
    }

    async fn read_context(RequestContextPattern(context): RequestContextPattern) -> String {
        context.request_id().unwrap_or("missing").to_owned()
    }

    struct RequestContextPattern(RequestContext);

    impl<S> FromRequestParts<S> for RequestContextPattern
    where
        S: Send + Sync,
    {
        type Rejection = std::convert::Infallible;

        async fn from_request_parts(
            parts: &mut http::request::Parts,
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            RequestContext::from_request_parts(parts, state)
                .await
                .map(Self)
        }
    }

    async fn response_body(response: Response) -> serde_json::Value {
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();
        serde_json::from_slice(&body).expect("response body should be JSON")
    }

    #[tokio::test]
    async fn validated_json_rejects_blank_field() {
        let app = Router::new().route("/things", post(create_thing));
        let request = http::Request::builder()
            .method("POST")
            .uri("/things")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"name": ""}"#))
            .expect("build request");

        let response = app.oneshot(request).await.expect("route response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_body(response).await;
        assert_eq!(body["error"], "VALIDATION_ERROR");
        assert_eq!(body["details"][0]["issue"], "name");
    }

    #[tokio::test]
    async fn pagination_defaults_and_caps_limit() {
        let app = Router::new().route("/things", get(read_pagination));
        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/things?page=2&limit=9999")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        assert_eq!(body["page"], 2);
        assert_eq!(body["limit"], MAX_PAGE_SIZE);
    }

    #[tokio::test]
    async fn request_context_reads_request_id_header_without_logging_middleware() {
        let app = Router::new().route("/context", get(read_context));
        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/context")
                    .header(X_REQUEST_ID, "request-123")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn idempotency_key_extractor_reads_standard_header() {
        let app = Router::new().route("/orders", post(read_idempotency_key));
        let response = app
            .oneshot(
                http::Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header("idempotency-key", "order-create-123")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn idempotency_key_extractor_rejects_missing_header() {
        let app = Router::new().route("/orders", post(read_idempotency_key));
        let response = app
            .oneshot(
                http::Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_body(response).await;
        assert_eq!(body["error"], "IDEMPOTENCY_KEY_REQUIRED");
    }
}
