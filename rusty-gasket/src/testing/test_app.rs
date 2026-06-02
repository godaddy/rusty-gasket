//! In-process HTTP test harness.
//!
//! [`TestApp`] wraps an axum `Router` and dispatches requests directly
//! via `Router::oneshot()` — no TCP listener, no port allocation, no
//! network overhead. Combine with [`MockAuthBackend`] to test authenticated
//! endpoints without real JWT infrastructure.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request};
use axum::middleware;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rusty_gasket::auth::{AuthChain, AuthMiddlewareState, UnauthenticatedPolicy, auth_middleware};
use rusty_gasket::observability;

use rusty_gasket::testing::mock_auth::MockAuthBackend;
use rusty_gasket::testing::test_response::TestResponse;

/// A test harness that wraps an axum `Router` for in-process HTTP testing.
///
/// Uses `Router::oneshot()` from Tower's `ServiceExt` — no TCP listener,
/// no port allocation, no network overhead. Requests are dispatched
/// directly to the router.
///
/// # Example
///
/// ```ignore
/// let app = TestApp::builder()
///     .mock_auth("test-user")
///     .router(my_router)
///     .build();
///
/// let resp = app.get("/v1/entities").await;
/// assert_eq!(resp.status(), StatusCode::OK);
/// ```
pub struct TestApp {
    router: Router,
}

impl std::fmt::Debug for TestApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestApp").finish_non_exhaustive()
    }
}

impl TestApp {
    /// Create a builder for configuring the test app.
    pub const fn builder() -> TestAppBuilder {
        TestAppBuilder {
            router: None,
            mock_auth: None,
            auth_state: None,
            add_logging: false,
        }
    }

    /// Send a GET request to the given path.
    pub async fn get(&self, path: &str) -> TestResponse {
        self.request(Method::GET, path, Body::empty()).await
    }

    /// Send a POST request with a JSON body.
    ///
    /// # Panics
    /// Panics if `body` cannot be serialized to JSON, if `path` is not a
    /// valid URI, or if the underlying router fails — any of which indicates
    /// a test bug rather than a runtime condition worth recovering from.
    pub async fn post_json(&self, path: &str, body: &impl serde::Serialize) -> TestResponse {
        let json = serde_json::to_vec(body).expect("serialize JSON body");
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        self.send(request).await
    }

    /// Send a PUT request with a JSON body.
    ///
    /// # Panics
    /// Panics if `body` cannot be serialized to JSON, if `path` is not a
    /// valid URI, or if the underlying router fails.
    pub async fn put_json(&self, path: &str, body: &impl serde::Serialize) -> TestResponse {
        let json = serde_json::to_vec(body).expect("serialize JSON body");
        let request = Request::builder()
            .method(Method::PUT)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        self.send(request).await
    }

    /// Send a DELETE request.
    pub async fn delete(&self, path: &str) -> TestResponse {
        self.request(Method::DELETE, path, Body::empty()).await
    }

    /// Send a PATCH request with a JSON body.
    ///
    /// # Panics
    /// Panics if `body` cannot be serialized to JSON, if `path` is not a
    /// valid URI, or if the underlying router fails.
    pub async fn patch_json(&self, path: &str, body: &impl serde::Serialize) -> TestResponse {
        let json = serde_json::to_vec(body).expect("serialize JSON body");
        let request = Request::builder()
            .method(Method::PATCH)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        self.send(request).await
    }

    /// Send a request with an arbitrary method, path, and body.
    ///
    /// # Panics
    /// Panics if `path` is not a valid URI, or if the underlying router
    /// fails — both indicate test misuse.
    pub async fn request(&self, method: Method, path: &str, body: Body) -> TestResponse {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(body)
            .expect("build request");
        self.send(request).await
    }

    /// Send a fully constructed request.
    ///
    /// # Panics
    /// Panics if the router cannot service the request or if the response
    /// body cannot be collected. Both signal a test setup bug.
    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router should not fail");

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();

        TestResponse::new(status, headers, body)
    }
}

/// Builder for [`TestApp`].
#[must_use = "TestAppBuilder must be consumed by .build() to produce a TestApp"]
pub struct TestAppBuilder {
    router: Option<Router>,
    mock_auth: Option<MockAuthBackend>,
    auth_state: Option<Arc<AuthMiddlewareState>>,
    add_logging: bool,
}

impl std::fmt::Debug for TestAppBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAppBuilder")
            .field("has_router", &self.router.is_some())
            .field("has_mock_auth", &self.mock_auth.is_some())
            .field("add_logging", &self.add_logging)
            .finish()
    }
}

impl TestAppBuilder {
    /// Set the application router to test against.
    pub fn router(mut self, router: Router) -> Self {
        self.router = Some(router);
        self
    }

    /// Add a mock auth backend that always authenticates as the given subject.
    pub fn mock_auth(mut self, subject: &str) -> Self {
        self.mock_auth = Some(MockAuthBackend::authenticated(subject));
        self
    }

    /// Add a mock auth backend with a custom identity.
    pub fn mock_auth_identity(mut self, identity: rusty_gasket::auth::Identity) -> Self {
        self.mock_auth = Some(MockAuthBackend::with_identity(identity));
        self
    }

    /// Add a mock auth backend that allows anonymous access.
    pub fn anonymous_auth(mut self) -> Self {
        self.mock_auth = Some(MockAuthBackend::anonymous());
        self
    }

    /// Provide a custom auth middleware state instead of mock auth.
    pub fn auth_state(mut self, state: Arc<AuthMiddlewareState>) -> Self {
        self.auth_state = Some(state);
        self
    }

    /// Enable or disable the logging middleware on the test router.
    /// Off by default to keep test output clean.
    pub const fn logging(mut self, enabled: bool) -> Self {
        self.add_logging = enabled;
        self
    }

    /// Build the `TestApp`.
    ///
    /// # Panics
    /// Panics if no router was provided, or if both `auth_state` and
    /// any of the `*_auth` mock-auth setters were configured — those
    /// are mutually exclusive and the combination would silently drop one,
    /// which has caused tests to lie about what they verify.
    pub fn build(self) -> TestApp {
        let router = self.router.expect("TestApp requires a router");

        assert!(
            !(self.auth_state.is_some() && self.mock_auth.is_some()),
            "TestAppBuilder cannot combine with_auth_state with with_mock_auth*; \
             pick one auth source per TestApp",
        );

        let router = if let Some(state) = self.auth_state {
            router.layer(middleware::from_fn_with_state(state, auth_middleware))
        } else if let Some(mock) = self.mock_auth {
            let fallback = if mock.is_anonymous() {
                UnauthenticatedPolicy::AllowAnonymous
            } else {
                UnauthenticatedPolicy::Reject
            };
            let state = Arc::new(AuthMiddlewareState::new(
                AuthChain::new().backend(mock).with_fallback(fallback),
            ));
            router.layer(middleware::from_fn_with_state(state, auth_middleware))
        } else {
            router
        };

        let router = if self.add_logging {
            router.layer(middleware::from_fn(observability::logging_middleware))
        } else {
            router
        };

        TestApp { router }
    }
}
