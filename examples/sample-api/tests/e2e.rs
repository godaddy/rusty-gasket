#![allow(clippy::unwrap_used)]

//! End-to-end tests for sample-api.
//!
//! These tests boot the full application stack (plugins, middleware, routes)
//! on a random OS-assigned port and exercise the HTTP API through real TCP
//! connections via `reqwest`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::middleware;
use tokio::net::TcpListener;

use rusty_gasket::config::AppConfigDefinition;
use rusty_gasket::observability;
use rusty_gasket::plugin::{GasketApp, RouteGroup};
use rusty_gasket::presets;

/// Replicate the route assembly from `server::build_router` (which is private).
fn build_router(app: &GasketApp) -> Router {
    let tagged_routes = app.collect_routes();
    let tagged_layers = app.collect_layers();

    let mut bare_router = Router::new();
    let mut public_router = Router::new();
    let mut protected_router = Router::new();

    for tagged in tagged_routes {
        match tagged.group {
            RouteGroup::Bare => bare_router = bare_router.merge(tagged.router),
            RouteGroup::Public => public_router = public_router.merge(tagged.router),
            RouteGroup::Protected => protected_router = protected_router.merge(tagged.router),
            _ => {}
        }
    }

    let logged_public = public_router.layer(middleware::from_fn(observability::logging_middleware));

    let mut protected_router = protected_router;
    for tagged_layer in tagged_layers.into_iter().rev() {
        protected_router = tagged_layer.layer.apply(protected_router);
    }
    let protected_router =
        protected_router.layer(middleware::from_fn(observability::logging_middleware));

    Router::new()
        .merge(bare_router)
        .merge(logged_public)
        .merge(protected_router)
}

/// Build the sample-api app and start it on a random port.
/// Returns the base URL and a handle to the background server task.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    // Use the same config as main.rs but port 0 is not used — we bind
    // ourselves and pass the router directly to axum::serve.
    let config = AppConfigDefinition::new("sample-api")
        .server(rusty_gasket::config::ServerConfig::new("127.0.0.1", 0));

    // Build the app exactly as main.rs does, but we skip ServerPlugin since
    // we drive the server ourselves.
    let app = GasketApp::builder()
        .preset(presets::api())
        .plugin(sample_api::AppPlugin)
        .config(config)
        .build()
        .await
        .unwrap();

    let app = Arc::new(app);
    let router = build_router(&app);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Notify plugins the server is ready.
    app.ready(addr).await.unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{addr}");
    (base_url, handle)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn healthcheck_returns_ok() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .get(format!("{base_url}/healthcheck"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(
        body.get("pkgVersion").is_some(),
        "healthcheck should include pkgVersion"
    );

    handle.abort();
}

#[tokio::test]
async fn livez_returns_ok() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .get(format!("{base_url}/livez"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    handle.abort();
}

#[tokio::test]
async fn list_items_returns_empty_array() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .get(format!("{base_url}/v1/items"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);

    handle.abort();
}

#[tokio::test]
async fn create_item_returns_201() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .post(format!("{base_url}/v1/items"))
        .json(&serde_json::json!({
            "name": "Widget",
            "description": "A useful widget",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "Widget");
    assert_eq!(body["description"], "A useful widget");
    assert!(body.get("id").is_some(), "created item should have an id");

    handle.abort();
}

#[tokio::test]
async fn create_then_get_item_by_id() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    // Create
    let create_resp = client
        .post(format!("{base_url}/v1/items"))
        .json(&serde_json::json!({
            "name": "Gadget",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(create_resp.status(), 201);
    let created: serde_json::Value = create_resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    // Get by ID
    let get_resp = client
        .get(format!("{base_url}/v1/items/{id}"))
        .send()
        .await
        .unwrap();

    assert_eq!(get_resp.status(), 200);
    let fetched: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(fetched["id"], id);
    assert_eq!(fetched["name"], "Gadget");
    assert!(fetched["description"].is_null());

    handle.abort();
}

#[tokio::test]
async fn create_then_list_items() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    // Create two items
    client
        .post(format!("{base_url}/v1/items"))
        .json(&serde_json::json!({"name": "Item A"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base_url}/v1/items"))
        .json(&serde_json::json!({"name": "Item B"}))
        .send()
        .await
        .unwrap();

    // List
    let resp = client
        .get(format!("{base_url}/v1/items"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let items: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(items.len(), 2);

    handle.abort();
}

#[tokio::test]
async fn get_nonexistent_item_returns_404() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let fake_id = uuid::Uuid::now_v7();
    let resp = client
        .get(format!("{base_url}/v1/items/{fake_id}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "NOT_FOUND");

    handle.abort();
}

#[tokio::test]
async fn x_request_id_echoed_back() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let custom_id = "test-request-id-12345";
    let resp = client
        .get(format!("{base_url}/healthcheck"))
        .header("X-Request-ID", custom_id)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("X-Request-ID")
            .and_then(|v| v.to_str().ok()),
        Some(custom_id),
        "server should echo back the X-Request-ID header"
    );

    handle.abort();
}

#[tokio::test]
async fn request_id_generated_when_not_provided() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .get(format!("{base_url}/healthcheck"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let request_id = resp
        .headers()
        .get("X-Request-ID")
        .expect("server should generate an X-Request-ID if none provided");
    let request_id = request_id.to_str().unwrap();
    assert!(
        !request_id.is_empty(),
        "generated request ID should not be empty"
    );

    handle.abort();
}

#[tokio::test]
async fn nonexistent_route_returns_404() {
    let (base_url, handle) = start_server().await;
    let client = http_client();

    let resp = client
        .get(format!("{base_url}/v1/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);

    handle.abort();
}
