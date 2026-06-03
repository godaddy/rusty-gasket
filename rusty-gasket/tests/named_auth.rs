//! Integration tests for named protected authentication chains.
//!
//! Exercises the end-to-end wiring of
//! [`RouteGroup::ProtectedWith`](rusty_gasket::plugin::RouteGroup::ProtectedWith)
//! and [`GasketAppBuilder::auth_chain`](rusty_gasket::plugin::GasketAppBuilder::auth_chain):
//! a single app serves one endpoint behind a static shared Bearer token,
//! one behind the normal (default) chain, and one public endpoint, and the
//! three credential domains stay isolated from one another.
//!
//! These tests assert through real HTTP status codes against a router built
//! exactly the way `ServerPlugin::run` builds it, so they cover the engine's
//! per-name middleware assembly, not just the backend in isolation.
#![cfg(feature = "auth")]
// Tests may panic/unwrap freely; that is how assertions surface failures.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use rusty_gasket::auth::{
    AuthBackend, AuthChain, AuthError, AuthMiddlewareState, Identity, StaticBearerBackend,
    UnauthenticatedPolicy, auth_middleware,
};
use rusty_gasket::pipeline::MiddlewareSlot;
use rusty_gasket::plugin::{GasketApp, Plugin, RouteContext, RouteGroup, TaggedLayer, TaggedRoute};

/// Bearer token accepted by the default (global) chain.
const DEFAULT_TOKEN: &str = "default-chain-token";
/// Bearer token accepted by the named "push" chain.
const PUSH_TOKEN: &str = "push-chain-token";
/// Body limit small enough to test the 413 path without large allocations.
const SMALL_BODY_LIMIT: usize = 32;

/// A minimal default-chain backend: authenticates one fixed Bearer token,
/// and defers (`Ok(None)`) on anything else so the chain's `Reject`
/// fallback turns unknown credentials into a 401.
#[derive(Debug)]
struct DefaultTokenBackend;

impl AuthBackend for DefaultTokenBackend {
    fn name(&self) -> &'static str {
        "test-default"
    }

    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        let token = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match token {
            Some(t) if t == DEFAULT_TOKEN => {
                Ok(Some(Identity::new("default-user", "test-default")))
            }
            // Defer: a token we don't recognize is not ours to reject.
            _ => Ok(None),
        }
    }
}

/// Marker layer at the `Custom` slot used to prove the rest of the
/// protected stack still runs for a `ProtectedWith` route: it stamps a
/// response header that the test reads back.
const MARKER_HEADER: &str = "x-custom-slot-ran";

/// Plugin under test. Contributes:
/// - `POST /push`   tagged `ProtectedWith("push")`
/// - `POST /normal` tagged `Protected` (default chain)
/// - `POST /open`   tagged `Public`
///
/// and two layers:
/// - the default global auth chain at the `Authentication` slot
/// - a custom-slot marker layer (to verify non-auth protected layers
///   still apply to `ProtectedWith` routes).
#[derive(Debug, Clone, Copy)]
struct ApiPlugin;

async fn ok_handler() -> StatusCode {
    StatusCode::OK
}

/// Handler that consumes the request body before returning. Reading the
/// body is what drives the streaming `RequestBodyLimitLayer` to reject an
/// oversized payload with 413; a handler that ignores the body never
/// polls it and so never trips the limit.
async fn echo_len_handler(body: axum::body::Bytes) -> StatusCode {
    let _ = body.len();
    StatusCode::OK
}

impl Plugin for ApiPlugin {
    fn name(&self) -> &'static str {
        "test:named-auth-api"
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        vec![
            TaggedRoute::new(
                RouteGroup::ProtectedWith("push"),
                Router::new().route("/push", post(echo_len_handler)),
            ),
            TaggedRoute::new(
                RouteGroup::Protected,
                Router::new().route("/normal", post(ok_handler)),
            ),
            TaggedRoute::new(
                RouteGroup::Public,
                Router::new().route("/open", post(ok_handler)),
            ),
        ]
    }

    fn layers(&self, _ctx: &rusty_gasket::plugin::LayerContext) -> Vec<TaggedLayer> {
        let default_state = Arc::new(AuthMiddlewareState::new(
            AuthChain::new()
                .backend(DefaultTokenBackend)
                .with_fallback(UnauthenticatedPolicy::Reject),
        ));
        vec![
            TaggedLayer::new(MiddlewareSlot::Authentication, move |router: Router| {
                router.layer(axum::middleware::from_fn_with_state(
                    default_state,
                    auth_middleware,
                ))
            }),
            TaggedLayer::new(MiddlewareSlot::Custom, |router: Router| {
                router.layer(axum::middleware::map_response(
                    async |mut resp: axum::response::Response| {
                        resp.headers_mut()
                            .insert(MARKER_HEADER, http::HeaderValue::from_static("1"));
                        resp
                    },
                ))
            }),
        ]
    }
}

/// Build the router under test, registering the named "push" chain backed
/// by a [`StaticBearerBackend`]. `body_limit` lets a test tighten the cap
/// to exercise the 413 path.
async fn build_app(body_limit: usize) -> GasketApp {
    GasketApp::builder()
        .request_body_limit(body_limit)
        .plugin(ApiPlugin)
        .auth_chain(
            "push",
            AuthMiddlewareState::new(
                AuthChain::new()
                    .backend(StaticBearerBackend::new(PUSH_TOKEN).service_account(true))
                    .with_fallback(UnauthenticatedPolicy::Reject),
            ),
        )
        .build()
        .await
        .expect("app builds")
}

/// Dispatch a `POST` with an optional Bearer token and an empty body.
async fn post_request(
    router: &Router,
    path: &str,
    bearer: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(Method::POST).uri(path);
    if let Some(token) = bearer {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder.body(Body::empty()).expect("request builds");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router responds")
}

#[tokio::test]
async fn push_endpoint_accepts_push_token() {
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/push", Some(PUSH_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn push_endpoint_rejects_missing_token() {
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/push", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cross_chain_default_credential_rejected_on_push() {
    // The default chain's credential must not open the push endpoint.
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/push", Some(DEFAULT_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn normal_endpoint_accepts_default_token() {
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/normal", Some(DEFAULT_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn cross_chain_push_token_rejected_on_normal() {
    // The push token must not open the default-chain endpoint.
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/normal", Some(PUSH_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_endpoint_is_open() {
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/open", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_with_route_keeps_custom_slot_layer() {
    // A ProtectedWith route must still receive the non-auth protected
    // layers; the custom-slot marker layer stamps a header on success.
    let router = build_app(rusty_gasket::plugin::DEFAULT_REQUEST_BODY_LIMIT)
        .await
        .build_router();
    let resp = post_request(&router, "/push", Some(PUSH_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(MARKER_HEADER)
            .map(|v| v.to_str().unwrap()),
        Some("1"),
        "custom-slot layer must run for ProtectedWith routes",
    );
}

#[tokio::test]
async fn protected_with_route_enforces_body_limit() {
    // A ProtectedWith route must still get the request-body limit so an
    // oversized authenticated request is rejected with 413.
    let router = build_app(SMALL_BODY_LIMIT).await.build_router();
    let oversized = vec![b'a'; SMALL_BODY_LIMIT + 1];
    let request = Request::builder()
        .method(Method::POST)
        .uri("/push")
        .header(http::header::AUTHORIZATION, format!("Bearer {PUSH_TOKEN}"))
        .body(Body::from(oversized))
        .expect("request builds");
    let resp = router.oneshot(request).await.expect("router responds");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn body_limit_response_is_not_a_panic() {
    // Guard: a rejected oversized body should produce a clean 413 body,
    // not a torn connection.
    let router = build_app(SMALL_BODY_LIMIT).await.build_router();
    let oversized = vec![b'a'; SMALL_BODY_LIMIT + 1];
    let request = Request::builder()
        .method(Method::POST)
        .uri("/push")
        .header(http::header::AUTHORIZATION, format!("Bearer {PUSH_TOKEN}"))
        .body(Body::from(oversized))
        .expect("request builds");
    let resp = router.oneshot(request).await.expect("router responds");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Body must be collectible (no panic, no hang).
    let collected = resp.into_body().collect().await.expect("body collects");
    drop(collected);
}

/// Plugin that emits a `ProtectedWith` route for a name that is never
/// registered as a chain.
#[derive(Debug, Clone, Copy)]
struct UnregisteredPlugin;

impl Plugin for UnregisteredPlugin {
    fn name(&self) -> &'static str {
        "test:unregistered-chain"
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        vec![TaggedRoute::new(
            RouteGroup::ProtectedWith("never-registered"),
            Router::new().route("/x", post(ok_handler)),
        )]
    }
}

#[tokio::test]
async fn unregistered_named_chain_panics_at_build() {
    let app = GasketApp::builder()
        .plugin(UnregisteredPlugin)
        .build()
        .await
        .expect("app builds");

    // build_router is synchronous, so catch_unwind captures the startup
    // panic directly.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.build_router()));
    let err = result.expect_err("building a router with an unregistered named chain must panic");
    let message = err
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| err.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("never-registered"),
        "panic message should name the missing chain, got: {message:?}",
    );
}
