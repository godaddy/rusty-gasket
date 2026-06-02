//! Route handlers for the friendly recipe API.
//!
//! The handler signatures are intentionally ordinary Rust: extract state,
//! auth, path/query/body inputs, return typed JSON, and let `ApiError`
//! translate failures into HTTP responses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusty_gasket::auth::CurrentUser;
use rusty_gasket::prelude::{
    CacheTtl, Context, ObjectCache, PathParams, QueryParams, Validate, Validated, ValidationErrors,
    route_cache_get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DEFAULT_SEARCH_LIMIT: usize = 25;
const MAX_SEARCH_LIMIT: usize = 100;

/// Shared application state for the example API.
///
/// Real services usually replace this in-memory store with a database
/// repository. Keeping the store behind a named type avoids exposing
/// `Arc<Mutex<...>>` in handler signatures.
#[derive(Debug, Clone, Default)]
pub struct ApiState {
    orders: SharedOrders,
}

/// Thread-safe order storage used by the example.
///
/// The type name keeps the locking detail in one small place. Handlers call
/// `state.orders()` instead of repeating `Arc<Mutex<HashMap<...>>>`.
#[derive(Debug, Clone, Default)]
struct SharedOrders {
    orders: Arc<Mutex<HashMap<Uuid, Order>>>,
}

impl ApiState {
    /// Borrow the in-memory order store.
    fn orders(&self) -> Result<MutexGuard<'_, HashMap<Uuid, Order>>, ApiError> {
        self.orders
            .orders
            .lock()
            .map_err(|_| ApiError::internal("order store is unavailable"))
    }
}

/// Build routes that do not require authentication.
///
/// Public routes are good for health checks, readiness probes, docs, and small
/// utility endpoints that intentionally do not know who the caller is.
pub fn public_routes() -> Router {
    let cache = ObjectCache::memory();

    Router::new()
        .route(
            "/status",
            route_cache_get!(cache = cache, ttl = CacheTtl::seconds(10), handler = status),
        )
        .route("/v1/strings/upper", get(uppercase_text))
}

/// Build routes that require authentication.
///
/// `TestApp::mock_auth(...)` in the tests installs mock auth for these routes.
/// A production service would install a real JWT, API-key, or company-specific
/// auth backend in the protected middleware pipeline.
pub fn protected_routes() -> Router {
    protected_routes_with_state(ApiState::default())
}

/// Build protected routes with caller-provided state.
///
/// Tests use this helper to keep each test isolated with a fresh store.
pub fn protected_routes_with_state(state: ApiState) -> Router {
    Router::new()
        .route("/v1/me", get(current_user))
        .route("/v1/orders", get(search_orders).post(create_order))
        .route("/v1/orders/{order_id}", get(get_order))
        .with_state(state)
}

/// Response returned by `GET /status`.
#[derive(Debug, Serialize)]
struct StatusResponse {
    service: &'static str,
    status: &'static str,
}

/// Report basic service health.
async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        service: "recipe-api",
        status: "ok",
    })
}

/// Query string accepted by the string processing endpoint.
#[derive(Debug, Deserialize)]
struct UppercaseQuery {
    text: String,
}

/// Response returned by the string processing endpoint.
#[derive(Debug, Serialize)]
struct UppercaseResponse {
    original: String,
    upper: String,
}

/// Convert text to uppercase for `GET /v1/strings/upper`.
async fn uppercase_text(
    QueryParams(query): QueryParams<UppercaseQuery>,
) -> Json<UppercaseResponse> {
    Json(UppercaseResponse {
        upper: to_uppercase(&query.text),
        original: query.text,
    })
}

/// String processing helper that is easy to unit test without HTTP.
#[must_use]
pub fn to_uppercase(text: &str) -> String {
    text.trim().to_uppercase()
}

/// Request body accepted by `POST /v1/orders`.
#[derive(Debug, Deserialize)]
pub struct CreateOrderRequest {
    customer: String,
    items: Vec<String>,
}

impl Validate for CreateOrderRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.customer.trim().is_empty() {
            return Err(ValidationErrors::one("customer", "customer is required"));
        }
        if self.items.is_empty() {
            return Err(ValidationErrors::one(
                "items",
                "at least one item is required",
            ));
        }
        if self.items.iter().any(|item| item.trim().is_empty()) {
            return Err(ValidationErrors::one("items", "items cannot be blank"));
        }
        Ok(())
    }
}

impl CreateOrderRequest {
    /// Convert a validated request into a stored order.
    fn into_order(self, created_by: String) -> Order {
        Order {
            id: Uuid::now_v7(),
            customer: self.customer.trim().to_owned(),
            items: self
                .items
                .into_iter()
                .map(|item| item.trim().to_owned())
                .collect(),
            status: OrderStatus::Received,
            created_by,
        }
    }
}

/// Order status returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Received,
}

/// Order resource returned by create, get, and search endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub id: Uuid,
    pub customer: String,
    pub items: Vec<String>,
    pub status: OrderStatus,
    pub created_by: String,
}

/// Standard wrapper for endpoints that return one order.
#[derive(Debug, Serialize)]
struct OrderResponse {
    order: Order,
}

/// Create an order for the authenticated caller.
async fn create_order(
    Context(state): Context<ApiState>,
    CurrentUser(identity): CurrentUser,
    Validated(request): Validated<CreateOrderRequest>,
) -> Result<(StatusCode, Json<OrderResponse>), ApiError> {
    let order = request.into_order(identity.subject().to_owned());
    let mut orders = state.orders()?;
    orders.insert(order.id, order.clone());

    Ok((StatusCode::CREATED, Json(OrderResponse { order })))
}

/// Path parameters accepted by `GET /v1/orders/{order_id}`.
#[derive(Debug, Deserialize)]
struct OrderPath {
    order_id: Uuid,
}

/// Fetch one order by ID.
async fn get_order(
    Context(state): Context<ApiState>,
    PathParams(path): PathParams<OrderPath>,
) -> Result<Json<OrderResponse>, ApiError> {
    let orders = state.orders()?;
    let order = orders
        .get(&path.order_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("order was not found"))?;

    Ok(Json(OrderResponse { order }))
}

/// Query parameters accepted by `GET /v1/orders`.
#[derive(Debug, Deserialize)]
struct SearchOrdersQuery {
    customer: Option<String>,
    limit: Option<usize>,
}

/// Response returned by order search.
#[derive(Debug, Serialize)]
struct SearchOrdersResponse {
    orders: Vec<Order>,
    limit: usize,
}

/// Search orders by optional customer name.
async fn search_orders(
    Context(state): Context<ApiState>,
    QueryParams(query): QueryParams<SearchOrdersQuery>,
) -> Result<Json<SearchOrdersResponse>, ApiError> {
    let requested_limit = query.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
    let limit = requested_limit.min(MAX_SEARCH_LIMIT);
    let customer_filter = query.customer.as_deref().map(str::to_lowercase);

    let orders = state.orders()?;
    let mut matches: Vec<Order> = orders
        .values()
        .filter(|order| {
            customer_filter
                .as_ref()
                .is_none_or(|customer| order.customer.to_lowercase().contains(customer))
        })
        .take(limit)
        .cloned()
        .collect();
    matches.sort_by(|left, right| left.customer.cmp(&right.customer));

    Ok(Json(SearchOrdersResponse {
        orders: matches,
        limit,
    }))
}

/// Response returned by `GET /v1/me`.
#[derive(Debug, Serialize)]
struct CurrentUserResponse {
    subject: String,
    auth_method: &'static str,
    scopes: Vec<String>,
}

/// Return the authenticated caller as a simple JSON object.
async fn current_user(CurrentUser(identity): CurrentUser) -> Json<CurrentUserResponse> {
    let mut scopes: Vec<String> = identity.scopes().iter().map(String::from).collect();
    scopes.sort();

    Json(CurrentUserResponse {
        subject: identity.subject().to_owned(),
        auth_method: identity.auth_method(),
        scopes,
    })
}

/// JSON error body returned by this example.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

/// Small API error type used by the example handlers.
///
/// The public handler signatures stay readable (`Result<Json<T>, ApiError>`)
/// while this type centralizes status codes and JSON error formatting.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    /// Build a `404 Not Found` error.
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found".to_owned(),
            message: message.into(),
        }
    }

    /// Build a sanitized `500 Internal Server Error`.
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error".to_owned(),
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    /// Convert an application error into a JSON HTTP response.
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code,
            message: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use pretty_assertions::assert_eq;
    use rusty_gasket::testing::TestApp;
    use serde_json::json;

    fn test_app() -> TestApp {
        let router = public_routes().merge(protected_routes_with_state(ApiState::default()));

        TestApp::builder()
            .router(router)
            .mock_auth("user:example-user")
            .build()
    }

    #[test]
    fn uppercase_helper_trims_and_uppercases_text() {
        assert_eq!(to_uppercase(" hello Rust "), "HELLO RUST");
    }

    #[tokio::test]
    async fn public_status_endpoint_is_easy_to_call() {
        let app = test_app();

        let response = app.get("/status").await;

        response.assert_status(StatusCode::OK);
        assert_eq!(
            response.json_value(),
            json!({"service": "recipe-api", "status": "ok"})
        );
    }

    #[tokio::test]
    async fn public_string_processing_endpoint_returns_uppercase_text() {
        let app = test_app();

        let response = app.get("/v1/strings/upper?text=hello%20rust").await;

        response.assert_status(StatusCode::OK);
        assert_eq!(
            response.json_value(),
            json!({"original": "hello rust", "upper": "HELLO RUST"})
        );
    }

    #[tokio::test]
    async fn authenticated_user_can_create_fetch_and_search_orders() {
        let app = test_app();

        let create_response = app
            .post_json(
                "/v1/orders",
                &json!({"customer": "Acme", "items": ["widget", "gasket"]}),
            )
            .await;

        create_response.assert_status(StatusCode::CREATED);
        let created = create_response.json_value();
        let order_id = created["order"]["id"]
            .as_str()
            .expect("created order includes an id");
        assert_eq!(created["order"]["createdBy"], "user:example-user");

        let get_response = app.get(&format!("/v1/orders/{order_id}")).await;
        get_response.assert_status(StatusCode::OK);
        assert_eq!(get_response.json_value()["order"]["customer"], "Acme");

        let search_response = app.get("/v1/orders?customer=acme&limit=10").await;
        search_response.assert_status(StatusCode::OK);
        assert_eq!(search_response.json_value()["orders"][0]["id"], order_id);
    }

    #[tokio::test]
    async fn create_order_rejects_blank_input() {
        let app = test_app();

        let response = app
            .post_json("/v1/orders", &json!({"customer": "", "items": ["widget"]}))
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(response.json_value()["error"], "VALIDATION_ERROR");
    }

    #[tokio::test]
    async fn current_user_endpoint_reads_mock_auth_identity() {
        let app = test_app();

        let response = app.get("/v1/me").await;

        response.assert_status(StatusCode::OK);
        assert_eq!(response.json_value()["subject"], "user:example-user");
    }
}
