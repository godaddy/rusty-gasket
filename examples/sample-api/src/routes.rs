//! Application routes demonstrating the plugin pattern.
//!
//! Defines a simple CRUD-style API for "items" to show how to:
//! - Register routes via `Plugin::routes()`
//! - Use route groups (Protected endpoints)
//! - Return JSON responses
//! - Handle path parameters

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use rusty_gasket::plugin::{Plugin, RouteContext, RouteGroup, TaggedRoute};

/// An example domain entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

/// Request body for creating an item.
#[derive(Debug, Deserialize)]
pub struct CreateItemRequest {
    pub name: String,
    pub description: Option<String>,
}

/// In-memory store for the example (would be a database in production).
#[derive(Debug, Default, Clone)]
pub struct ItemStore {
    items: Arc<Mutex<Vec<Item>>>,
}

/// The application plugin that registers routes.
#[derive(Debug)]
pub struct AppPlugin;

impl Plugin for AppPlugin {
    fn name(&self) -> &'static str {
        "sample:app"
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        let store = ItemStore::default();

        let router = Router::new()
            .route("/v1/items", get(list_items).post(create_item))
            .route("/v1/items/{id}", get(get_item))
            .with_state(store);

        vec![TaggedRoute::new(RouteGroup::Protected, router)]
    }
}

/// List all items.
async fn list_items(State(store): State<ItemStore>) -> impl IntoResponse {
    let items = store.items.lock().expect("lock poisoned");
    Json(items.clone())
}

/// Create a new item.
async fn create_item(
    State(store): State<ItemStore>,
    Json(req): Json<CreateItemRequest>,
) -> impl IntoResponse {
    let item = Item {
        id: Uuid::now_v7(),
        name: req.name,
        description: req.description,
    };

    store
        .items
        .lock()
        .expect("lock poisoned")
        .push(item.clone());

    tracing::info!(id = %item.id, name = %item.name, "Item created");
    (StatusCode::CREATED, Json(item))
}

/// Get an item by ID.
async fn get_item(State(store): State<ItemStore>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let items = store.items.lock().expect("lock poisoned");

    match items.iter().find(|i| i.id == id) {
        Some(item) => (
            StatusCode::OK,
            Json(serde_json::to_value(item).expect("serialize")),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "NOT_FOUND", "message": "Item not found"})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_gasket::testing::TestApp;

    fn test_app() -> TestApp {
        let store = ItemStore::default();
        let router = Router::new()
            .route("/v1/items", get(list_items).post(create_item))
            .route("/v1/items/{id}", get(get_item))
            .with_state(store);

        TestApp::builder().router(router).build()
    }

    #[tokio::test]
    async fn list_items_empty() {
        let app = test_app();
        let resp = app.get("/v1/items").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let items: Vec<Item> = resp.json();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn create_and_list_items() {
        let app = test_app();

        let resp = app
            .post_json(
                "/v1/items",
                &serde_json::json!({"name": "Widget", "description": "A useful widget"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created: Item = resp.json();
        assert_eq!(created.name, "Widget");
        assert_eq!(created.description.as_deref(), Some("A useful widget"));
        assert!(!created.id.is_nil());

        let resp = app.get("/v1/items").await;
        let items: Vec<Item> = resp.json();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Widget");
    }

    #[tokio::test]
    async fn get_item_by_id() {
        let app = test_app();

        let resp = app
            .post_json("/v1/items", &serde_json::json!({"name": "Gadget"}))
            .await;
        let created: Item = resp.json();

        let resp = app.get(&format!("/v1/items/{}", created.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let fetched: Item = resp.json();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, "Gadget");
    }

    #[tokio::test]
    async fn get_nonexistent_item_returns_404() {
        let app = test_app();
        let fake_id = Uuid::now_v7();
        let resp = app.get(&format!("/v1/items/{fake_id}")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_item_without_description() {
        let app = test_app();
        let resp = app
            .post_json("/v1/items", &serde_json::json!({"name": "Bare item"}))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let item: Item = resp.json();
        assert_eq!(item.name, "Bare item");
        assert!(item.description.is_none());
    }
}
