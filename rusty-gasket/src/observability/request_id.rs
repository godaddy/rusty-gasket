//! Request ID generation and propagation.
//!
//! Each incoming request is assigned a UUID v7 (or inherits one from the
//! `X-Request-ID` header). The ID is stored in request extensions, set as
//! a task-local for access from any async context, and echoed back in
//! the response headers.

/// HTTP header name for request ID propagation.
pub const X_REQUEST_ID: &str = "X-Request-ID";

/// Request ID stored in axum request extensions by the logging middleware.
/// Other middleware (auth, transaction) reads this for correlation.
#[derive(Clone, Debug)]
pub struct RequestId(pub(crate) String);

impl RequestId {
    /// Access the request ID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Task-local request ID accessible from any async context within a request.
// Used by error handlers to attach correlation IDs without threading
// the ID through every function parameter.
tokio::task_local! {
    pub static CURRENT_REQUEST_ID: String;
}

/// Retrieve the current request's ID from task-local storage, if available.
/// Returns the raw string so non-UUID request IDs (e.g., from external
/// headers) are still available for correlation.
#[must_use]
pub fn current_request_id() -> Option<String> {
    CURRENT_REQUEST_ID.try_with(Clone::clone).ok()
}
