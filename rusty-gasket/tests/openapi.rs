//! Regression test for [`OpenApiPlugin`](rusty_gasket::openapi::OpenApiPlugin).
//!
//! `OpenApiPlugin::routes()` used to return *two* routes that both served
//! `GET /openapi.json` — an explicit spec route plus the Swagger-UI
//! `.url("/openapi.json", spec)` builder, which registers that path itself.
//! Building the router merged them and panicked with
//! "Overlapping method route. Handler for `GET /openapi.json` already exists",
//! so *any* service that registered the plugin crashed at startup.
//!
//! These tests build a router exactly the way the server does and assert that
//! (a) `build_router` no longer panics and (b) the spec is still served.
#![cfg(feature = "openapi")]
// Tests may panic/unwrap freely; that is how assertions surface failures.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt as _;
use utoipa::OpenApi;

use rusty_gasket::openapi::OpenApiPlugin;
use rusty_gasket::plugin::GasketApp;

/// A minimal API document — no paths or schemas are needed to reproduce the
/// duplicate-route defect, which was in route registration, not the spec.
#[derive(OpenApi)]
#[openapi()]
struct ApiDoc;

/// Build the router the way `ServerPlugin::run` does. The `build_router` call
/// is where the duplicate `/openapi.json` route used to panic.
async fn router() -> Router {
    GasketApp::builder()
        .plugin(OpenApiPlugin::from_api_doc::<ApiDoc>())
        .build()
        .await
        .expect("app builds")
        .build_router()
}

#[tokio::test]
async fn build_router_does_not_panic_with_openapi_plugin() {
    // Construction alone is the regression check: before the fix this panicked
    // inside `build_router` while merging the plugin's overlapping routes.
    let _router = router().await;
}

#[tokio::test]
async fn openapi_json_route_is_served_once() {
    let resp = router()
        .await
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/openapi.json")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /openapi.json must still serve the spec after de-duplicating the route"
    );
}

#[tokio::test]
async fn swagger_ui_is_served() {
    let resp = router()
        .await
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/swagger-ui/")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the Swagger UI must still be served at /swagger-ui/"
    );
}
