# Testing

In-process HTTP testing with `TestApp`, mock authentication, ergonomic response assertions, and container-backed database tests.

## Overview

Enable the `testing` feature on `rusty-gasket` to use:

- **`TestApp`** -- in-process HTTP test harness (no TCP listener, no network)
- **`TestResponse`** -- ergonomic response wrapper for assertions
- **`MockAuthBackend`** -- fake auth that returns fixed identities

## TestApp

`TestApp` wraps an axum `Router` and dispatches requests directly via `Router::oneshot()` from Tower's `ServiceExt`. No TCP listener, no port allocation, no network overhead.

### Builder API

```rust
use rusty_gasket::testing::TestApp;

let app = TestApp::builder()
    .router(my_router)           // required: the router to test
    .with_mock_auth("test-user") // optional: mock authentication
    .with_logging()              // optional: enable logging middleware
    .build();
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `.router(router)` | Set the axum `Router` to test against (required) |
| `.with_mock_auth(subject)` | Always authenticate as the given subject |
| `.with_mock_auth_identity(identity)` | Authenticate with a custom `Identity` |
| `.with_anonymous_auth()` | Allow anonymous access (no identity) |
| `.with_auth_state(state)` | Use a custom `AuthMiddlewareState` |
| `.with_logging()` | Add the logging middleware (off by default for clean test output) |

### Request Methods

```rust
// GET
let resp = app.get("/v1/items").await;

// POST with JSON body
let resp = app.post_json("/v1/items", &serde_json::json!({"name": "Widget"})).await;

// PUT with JSON body
let resp = app.put_json("/v1/items/123", &item).await;

// DELETE
let resp = app.delete("/v1/items/123").await;

// PATCH with JSON body
let resp = app.patch_json("/v1/items/123", &update).await;

// Arbitrary method and body
let resp = app.request(Method::OPTIONS, "/v1/items", Body::empty()).await;

// Fully constructed request (for custom headers, etc.)
let request = Request::builder()
    .method(Method::GET)
    .uri("/v1/items")
    .header("X-Custom-Header", "value")
    .body(Body::empty())
    .unwrap();
let resp = app.send(request).await;
```

## TestResponse

`TestResponse` collects status, headers, and body bytes upfront so tests can make multiple assertions without dealing with the async body stream.

```rust
let resp = app.get("/v1/items").await;

// Status code
assert_eq!(resp.status(), StatusCode::OK);

// Parse JSON body into a typed struct
let items: Vec<Item> = resp.json();
assert_eq!(items.len(), 1);

// Parse as serde_json::Value
let value = resp.json_value();
assert_eq!(value["status"], "ok");

// Raw text
let body = resp.text();
assert!(body.contains("hello"));

// Raw bytes
let bytes = resp.bytes();

// Headers
assert!(resp.headers().contains_key("content-type"));
```

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `status()` | `StatusCode` | HTTP status code |
| `headers()` | `&HeaderMap` | Response headers |
| `json::<T>()` | `T` | Parse body as JSON (panics on failure) |
| `json_value()` | `serde_json::Value` | Parse body as generic JSON |
| `text()` | `&str` | Body as UTF-8 string (panics if invalid) |
| `bytes()` | `&Bytes` | Raw body bytes |

The panic behavior on parse failure is intentional in test code -- invalid JSON or UTF-8 in a response is itself a test failure.

## MockAuthBackend

Returns a fixed identity without performing any real token validation. Three modes:

```rust
use rusty_gasket::testing::MockAuthBackend;

// Always authenticates as "test-user"
let backend = MockAuthBackend::authenticated("test-user");

// Authenticates with a custom identity (scopes, display name, etc.)
let identity = Identity::builder("admin", "mock")
    .scope("admin")
    .scope("read")
    .display_name("Test Admin")
    .build();
let backend = MockAuthBackend::with_identity(identity);

// Never matches (returns Ok(None)) -- for anonymous testing
let backend = MockAuthBackend::anonymous();
```

### Using with TestApp

```rust
// Simple: always authenticated
let app = TestApp::builder()
    .with_mock_auth("test-user")
    .router(my_router)
    .build();

// Custom identity with scopes
let app = TestApp::builder()
    .with_mock_auth_identity(
        Identity::builder("admin", "mock")
            .scope("admin")
            .build()
    )
    .router(my_router)
    .build();

// Anonymous access
let app = TestApp::builder()
    .with_anonymous_auth()
    .router(my_router)
    .build();
```

When `with_mock_auth()` is used, the builder automatically configures an `AuthChain` with `UnauthenticatedPolicy::Reject`. When `with_anonymous_auth()` is used, it uses `UnauthenticatedPolicy::AllowAnonymous`.

## Testing Patterns

### Basic CRUD Test

```rust
#[tokio::test]
async fn crud_lifecycle() {
    let store = ItemStore::default();
    let router = Router::new()
        .route("/v1/items", get(list_items).post(create_item))
        .route("/v1/items/{id}", get(get_item))
        .with_state(store);

    let app = TestApp::builder().router(router).build();

    // List (empty)
    let resp = app.get("/v1/items").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let items: Vec<Item> = resp.json();
    assert!(items.is_empty());

    // Create
    let resp = app.post_json("/v1/items", &serde_json::json!({
        "name": "Widget",
        "description": "A useful widget"
    })).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: Item = resp.json();
    assert_eq!(created.name, "Widget");

    // Get by ID
    let resp = app.get(&format!("/v1/items/{}", created.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let fetched: Item = resp.json();
    assert_eq!(fetched.id, created.id);
}
```

### Testing Auth-Protected Endpoints

```rust
#[tokio::test]
async fn protected_endpoint_requires_auth() {
    let router = Router::new()
        .route("/v1/secret", get(secret_handler));

    // Without auth -- handler never sees request extensions with AuthContext
    let app = TestApp::builder().router(router.clone()).build();
    // (No auth middleware, handler relies on extractors)

    // With mock auth
    let app = TestApp::builder()
        .with_mock_auth("test-user")
        .router(router)
        .build();

    let resp = app.get("/v1/secret").await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Testing Error Responses

```rust
#[tokio::test]
async fn not_found_returns_structured_error() {
    let app = TestApp::builder().router(my_router).build();

    let resp = app.get("/v1/items/nonexistent").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = resp.json_value();
    assert_eq!(body["error"], "NOT_FOUND");
    assert!(body["message"].as_str().unwrap().contains("not found"));
}
```

### Testing with Custom Headers

```rust
use axum::body::Body;
use axum::http::Request;

#[tokio::test]
async fn custom_header_test() {
    let app = TestApp::builder().router(my_router).build();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/items")
        .header("X-Tenant-ID", "tenant-42")
        .body(Body::empty())
        .unwrap();

    let resp = app.send(request).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

## Container-Backed Tests

For integration tests that need a real database, use testcontainers:

```rust
use testcontainers::{GenericImage, runners::AsyncRunner};
use sqlx::AnyPool;

#[tokio::test]
async fn database_integration_test() {
    // Start a temporary PostgreSQL container
    let container = GenericImage::new("postgres", "16-alpine")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "testdb")
        .start()
        .await
        .expect("start container");

    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:test@127.0.0.1:{port}/testdb");

    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&url).await.expect("connect");

    // Run migrations or setup
    sqlx::query("CREATE TABLE items (id UUID PRIMARY KEY, name TEXT NOT NULL)")
        .execute(&pool)
        .await
        .expect("create table");

    // Test your handler with a real database
    let router = Router::new()
        .route("/v1/items", get(list_items))
        .with_state(pool.clone());

    let app = TestApp::builder().router(router).build();
    let resp = app.get("/v1/items").await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

Container-backed tests require Docker. Guard them with an ignore attribute or feature flag if your CI does not have Docker:

```rust
#[tokio::test]
#[ignore = "requires Docker"]
async fn container_test() { /* ... */ }
```

Run ignored tests explicitly:

```bash
cargo test -- --ignored
```

## Benchmarking with Criterion

The `bench-api` example demonstrates in-process benchmarks using criterion:

```rust
use criterion::{Criterion, criterion_group, criterion_main, black_box};
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

fn bench_endpoint(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let router = build_my_router();

    c.bench_function("my_endpoint", |b| {
        b.to_async(&rt).iter(|| {
            let r = router.clone();
            async move {
                let req = Request::builder()
                    .uri("/v1/data")
                    .body(Body::empty())
                    .unwrap();
                let resp = r.oneshot(req).await.unwrap();
                black_box(resp);
            }
        });
    });
}

criterion_group!(benches, bench_endpoint);
criterion_main!(benches);
```

Uses `Router::oneshot()` -- same mechanism as `TestApp` -- so benchmarks measure framework overhead without network I/O.

Run benchmarks:

```bash
cargo bench -p bench-api
```

## Tips

- Keep `with_logging()` off by default in tests to reduce noise. Enable it when debugging a specific test.
- Use `with_mock_auth_identity()` to test scope-based authorization.
- `TestResponse::json()` panics on parse failure -- this is intentional so parse errors surface as test failures.
- For complex setups, use `TestApp::builder().with_auth_state(state)` with a custom `AuthMiddlewareState` containing a real `AuthChain`.

## Further Reading

- [Authentication](authentication.md) -- `MockAuthBackend` and auth testing
- [Database](database.md) -- testcontainers for database tests
- [Error Handling](error-handling.md) -- testing structured error responses
