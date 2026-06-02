//! Mock authentication backend for testing.
//!
//! Returns a fixed identity (or `None` for anonymous testing) without
//! performing any real token or credential validation. Use this to
//! exercise handler logic behind auth extractors in integration tests.

use rusty_gasket::auth::backend::AuthBackend;
use rusty_gasket::auth::{AuthError, Identity};

/// A mock authentication backend for testing.
///
/// Always returns a fixed identity (or None for anonymous testing).
/// No real token validation is performed — this is purely for
/// exercising handler logic behind auth extractors.
///
/// # Example
///
/// ```ignore
/// let backend = MockAuthBackend::authenticated("test-user");
/// let backend = MockAuthBackend::anonymous();
/// ```
#[derive(Debug, Clone)]
pub struct MockAuthBackend {
    identity: Option<Identity>,
}

impl MockAuthBackend {
    /// Create a backend that always authenticates as the given subject.
    #[must_use]
    pub fn authenticated(subject: &str) -> Self {
        Self {
            identity: Some(Identity::new(subject, "mock")),
        }
    }

    /// Create a backend that always authenticates with a full identity.
    #[must_use]
    pub const fn with_identity(identity: Identity) -> Self {
        Self {
            identity: Some(identity),
        }
    }

    /// Create a backend that never matches (returns `Ok(None)`).
    #[must_use]
    pub const fn anonymous() -> Self {
        Self { identity: None }
    }

    /// Whether this mock is configured for anonymous (no-identity) mode.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.identity.is_none()
    }
}

impl AuthBackend for MockAuthBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn authenticate(
        &self,
        _headers: &http::HeaderMap,
        _uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        Ok(self.identity.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_authenticated() {
        let backend = MockAuthBackend::authenticated("user-1");
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "/test".parse().expect("valid uri");

        let result = backend
            .authenticate(&headers, &uri)
            .await
            .expect("should succeed");
        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "user-1");
        assert_eq!(identity.auth_method(), "mock");
    }

    #[tokio::test]
    async fn mock_anonymous() {
        let backend = MockAuthBackend::anonymous();
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "/test".parse().expect("valid uri");

        let result = backend
            .authenticate(&headers, &uri)
            .await
            .expect("should succeed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mock_with_custom_identity() {
        let identity = Identity::builder("custom-user", "custom")
            .display_name("Custom User")
            .scope("admin")
            .scope("read")
            .build();

        let backend = MockAuthBackend::with_identity(identity);
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "/test".parse().expect("valid uri");

        let result = backend
            .authenticate(&headers, &uri)
            .await
            .expect("should succeed");
        let id = result.expect("should have identity");
        assert_eq!(id.subject(), "custom-user");
        assert_eq!(id.display_name(), Some("Custom User"));
        assert!(id.has_scope("admin"));
        assert!(id.has_scope("read"));
    }
}
