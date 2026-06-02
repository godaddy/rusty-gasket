//! Ergonomic response wrapper for test assertions.
//!
//! [`TestResponse`] collects the response status, headers, and body bytes
//! upfront so tests can make multiple assertions without dealing with the
//! async body stream.

use axum::http::StatusCode;
use bytes::Bytes;

/// Ergonomic wrapper around an HTTP response for test assertions.
///
/// Provides convenient methods for checking status codes, parsing
/// JSON bodies, and reading response text without manually collecting
/// the body stream.
#[derive(Debug)]
pub struct TestResponse {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

impl TestResponse {
    pub(crate) const fn new(status: StatusCode, headers: http::HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// The HTTP status code.
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers.
    pub const fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// The raw response body as bytes.
    pub const fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// The response body as a UTF-8 string.
    ///
    /// # Panics
    /// Panics if the body is not valid UTF-8. This is intentional in
    /// test code — invalid UTF-8 in a response is itself a test failure.
    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("response body is not valid UTF-8")
    }

    /// Parse the response body as JSON into the given type.
    ///
    /// # Panics
    /// Panics if deserialization fails. This is intentional in test code.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("response body is not valid JSON")
    }

    /// Convenience: get a specific JSON field as a `serde_json::Value`.
    ///
    /// # Panics
    /// Panics if the body is not valid JSON.
    pub fn json_value(&self) -> serde_json::Value {
        self.json()
    }

    /// Assert that the response has the expected status code.
    /// Produces a clear error message including the actual status and body.
    ///
    /// # Panics
    /// Panics if the status code does not match.
    pub fn assert_status(&self, expected: StatusCode) {
        assert_eq!(
            self.status,
            expected,
            "Expected status {expected}, got {}. Body: {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
    }

    /// Assert that the response is a standard JSON error with the expected
    /// status code and error code string.
    ///
    /// Verifies:
    /// - Status matches `expected_status`
    /// - Body is valid JSON
    /// - `error` field matches `expected_code`
    /// - `correlationId` field is present
    ///
    /// # Panics
    /// Panics if any assertion fails.
    pub fn assert_json_error(&self, expected_status: StatusCode, expected_code: &str) {
        self.assert_status(expected_status);
        let json = self.json_value();
        assert_eq!(
            json["error"].as_str(),
            Some(expected_code),
            "Expected error code '{expected_code}', got {:?}. Full body: {json}",
            json["error"]
        );
        assert!(
            json["correlationId"].is_string(),
            "Missing correlationId in error response. Full body: {json}"
        );
    }
}
