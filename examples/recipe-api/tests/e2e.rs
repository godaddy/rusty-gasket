//! End-to-end checks for the recipe API routes.
//!
//! These tests use the public `TestApp` harness so the example stays close to
//! how application teams should test their own handlers.

use axum::http::StatusCode;
use pretty_assertions::assert_eq;
use recipe_api::routes;
use rusty_gasket::testing::TestApp;
use serde_json::json;

#[tokio::test]
async fn protected_routes_require_auth_when_no_auth_backend_is_installed() {
    let router = routes::public_routes().merge(routes::protected_routes());
    let app = TestApp::builder().router(router).build();

    let response = app.get("/v1/me").await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_routes_work_with_mock_auth_in_tests() {
    let router = routes::public_routes().merge(routes::protected_routes());
    let app = TestApp::builder()
        .router(router)
        .mock_auth("user:test-user")
        .build();

    let response = app
        .post_json(
            "/v1/orders",
            &json!({"customer": "ExampleCo", "items": ["domain"]}),
        )
        .await;

    response.assert_status(StatusCode::CREATED);
    assert_eq!(
        response.json_value()["order"]["createdBy"],
        "user:test-user"
    );
}
