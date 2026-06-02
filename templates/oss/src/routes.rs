//! Application routes and handlers.
//!
//! All routes are registered via the [`AppPlugin`], which implements
//! the [`Plugin`] trait. The plugin contributes routes to the framework
//! during the `routes()` lifecycle phase.
//!
//! Routes are assigned to route groups that determine their middleware:
//! - `Bare` — no middleware (liveness probes)
//! - `Public` — logging only (health checks, docs)
//! - `Protected` — full middleware stack (auth, rate limiting, etc.)

use axum::routing::get;
use axum::{Json, Router};

use rusty_gasket::plugin::{Plugin, RouteContext, RouteGroup, TaggedRoute};

/// The main application plugin that registers all API routes.
///
/// Add your routes in the `routes()` method. For larger applications,
/// split routes across multiple plugins (e.g., `UsersPlugin`,
/// `OrdersPlugin`) to keep each module focused.
pub struct AppPlugin;

impl Plugin for AppPlugin {
    fn name(&self) -> &'static str {
        "app"
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        let router = Router::new().route("/v1/hello", get(hello));

        vec![TaggedRoute::new(RouteGroup::Protected, router)]
    }
}

/// Simple greeting endpoint.
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({"message": "Hello from Rusty Gasket!"}))
}

// See https://docs.rs/rusty-gasket for examples of path/state/JSON
// extractors and the `ApiError` derive macro.
