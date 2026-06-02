# Middleware

Pipeline slot ordering, route groups, and writing custom middleware.

## Overview

Rusty Gasket's middleware pipeline is divided into ordered slots. Plugins contribute layers to specific slots; the framework assembles them in slot order regardless of plugin registration order. This guarantees correct middleware ordering (logging before auth, auth before rate limiting) even as plugins are added or removed.

## MiddlewareSlot Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MiddlewareSlot {
    /// Outermost: CORS, HSTS, compression, body size limits.
    TransportSecurity = 0,

    /// Request ID generation, tracing span creation, structured logging.
    Logging = 10,

    /// Authentication and authorization.
    Authentication = 20,

    /// Per-client or per-IP rate limiting.
    RateLimit = 30,

    /// Per-request database transaction with request ID correlation.
    Transaction = 40,

    /// Application-specific middleware (closest to handlers).
    Custom = 50,
}
```

### Why These Slots

The ordering is intentional and informed by production experience:

| Slot | Why this position |
|------|------------------|
| **TransportSecurity** | CORS and compression run before everything so error responses get proper headers |
| **Logging** | Before auth so auth failures are logged with request IDs |
| **Authentication** | Before rate limiting so the rate limiter can use the client identity |
| **RateLimit** | Before transaction so rejected requests do not waste DB connections |
| **Transaction** | After rate limiting but before handlers |
| **Custom** | Closest to handlers -- application-specific concerns |

## TaggedLayer

Plugins contribute middleware as `TaggedLayer` -- a slot tag and a router transformation:

```rust
TaggedLayer::new(MiddlewareSlot::Authentication, |router| {
    router.layer(axum::middleware::from_fn(my_middleware))
})
```

The framework stores that closure internally so plugins do not need to name
the concrete Tower layer type.

### Why a Closure Instead of Tower Layer

Axum's `Router::layer()` accepts Tower layers, but composing multiple `BoxService` layers leads to type erasure issues. The closure approach wraps the router directly:

```rust
let layer = TaggedLayer::new(MiddlewareSlot::Custom, |router: Router| {
    router.layer(axum::middleware::from_fn(my_middleware))
});
```

## Built-In Middleware Plugins

Common production API middleware is available as plugins:

```rust
let app = GasketApp::builder()
    .plugin(CorsPlugin::default())
    .plugin(CompressionPlugin)
    .plugin(SecureHeadersPlugin)
    .plugin(TimeoutPlugin::from_secs(30))
    .plugin(AppPlugin)
    .build()
    .await?;
```

These plugins live in the `TransportSecurity` slot. The default CORS plugin is
strict; use `CorsPlugin::permissive_for_local_development()` only for local
examples or demos.

## How Layers are Applied

The server collects all layers from all plugins, sorts them by slot, and applies
them in reverse order. Reverse order is necessary because axum's `.layer()`
wraps from the outside -- the last layer applied is the outermost.

Transport-security layers wrap both `Public` and `Protected` routes. Other
plugin layers wrap only `Protected` routes. `Bare` routes remain unwrapped.

The logging middleware is applied separately because it also applies to
`Public` routes.

## Route Groups and Which Middleware Applies

Routes are tagged with a `RouteGroup` that determines which middleware stack they receive:

```rust
pub enum RouteGroup {
    /// No middleware at all.
    Bare,
    /// Transport security, logging, and request body limit.
    Public,
    /// Full middleware stack.
    Protected,
}
```

### What Each Group Gets

| Group | Layers applied |
|-------|---------------|
| `Bare` | None |
| `Public` | TransportSecurity + logging + request body limit |
| `Protected` | TransportSecurity + logging + request body limit + auth/rate-limit/transaction/custom plugin layers |

The server assembles three separate routers and merges them:

```rust
Router::new()
    .merge(bare_router)
    .merge(transport_wrapped_public_and_protected_router)
```

### Choosing a Route Group

| Use case | Group |
|----------|-------|
| Kubernetes liveness probe (`/livez`) | `Bare` |
| Health check (`/healthcheck`) | `Public` |
| OpenAPI spec, Swagger UI | `Public` |
| Application API endpoints | `Protected` |
| Liveness probes that must have zero overhead | `Bare` |

## Writing Custom Middleware

### Using from_fn

The simplest way to add custom middleware:

```rust
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

async fn my_middleware(request: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    tracing::debug!(duration_ms = duration.as_millis(), "custom timing");
    response
}
```

### Contributing from a Plugin

Register custom middleware in the `Custom` slot:

```rust
use rusty_gasket::pipeline::MiddlewareSlot;

impl Plugin for MyPlugin {
    fn name(&self) -> &'static str { "my-plugin" }

    fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> {
        vec![TaggedLayer::new(
            MiddlewareSlot::Custom,
            |router: Router| {
                router.layer(axum::middleware::from_fn(my_middleware))
            },
        )]
    }
}
```

### With Shared State

For middleware that needs shared state, use `from_fn_with_state`:

```rust
use std::sync::Arc;

#[derive(Debug, Clone)]
struct TenantConfig {
    default_tenant: String,
}

async fn tenant_middleware(
    axum::extract::State(config): axum::extract::State<Arc<TenantConfig>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Add default tenant header if missing
    if !request.headers().contains_key("x-tenant-id") {
        request.headers_mut().insert(
            "x-tenant-id",
            config.default_tenant.parse().unwrap(),
        );
    }
    next.run(request).await
}

impl Plugin for TenantPlugin {
    fn name(&self) -> &'static str { "tenant" }

    fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> {
        let config = Arc::new(TenantConfig {
            default_tenant: "default".into(),
        });

        vec![TaggedLayer::new(
            MiddlewareSlot::Custom,
            move |router: Router| {
                router.layer(axum::middleware::from_fn_with_state(config, tenant_middleware))
            },
        )]
    }
}
```

### Using Tower Layers

You can also use standard Tower layers:

```rust
use tower_http::cors::{Any, CorsLayer};

fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    vec![TaggedLayer::new(
        MiddlewareSlot::TransportSecurity,
        move |router: Router| router.layer(cors),
    )]
}
```

### Multiple Layers in One Plugin

A plugin can contribute layers to multiple slots:

```rust
fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> {
    vec![
        TaggedLayer::new(MiddlewareSlot::TransportSecurity, |router| {
            router.layer(cors_layer)
        }),
        TaggedLayer::new(MiddlewareSlot::Custom, |router| {
            router.layer(audit_layer)
        }),
    ]
}
```

## Built-in Middleware

### Logging Middleware

Applied to both `Public` and `Protected` routes. Creates a root tracing span per request with method, path, request ID, and timing. Auth fields are populated by the auth middleware via `LoggingContext`.

See [observability.md](observability.md) for details.

### Auth Middleware

Runs the `AuthChain`, populates `AuthContext` in request extensions, writes auth summary into `LoggingContext`.

See [authentication.md](authentication.md) for details.

### Rate Limit Middleware

Per-client token bucket rate limiting using Governor. Extracts the rate limit key from `RateLimitSubject` in request extensions (set by auth middleware).

```rust
pub async fn rate_limit_middleware(
    State(state): State<Arc<RateLimitState>>,
    request: Request,
    next: Next,
) -> Response;
```

Returns 429 Too Many Requests with a `Retry-After` header when the rate is exceeded. Exempt keys bypass rate limiting entirely.

### Transaction Middleware

Begins a per-request database transaction with request ID correlation. Stores the transaction in request extensions for the `DbTx` extractor.

See [database.md](database.md) for details.

## Rate Limiting Details

### Configuration

```rust
pub struct RateLimitConfig {
    pub enabled: bool,                    // default: true
    pub requests_per_minute: NonZeroU32,  // default: 60
    pub burst_size: NonZeroU32,           // default: 10
    pub exempt_keys: HashSet<String>,     // keys that bypass rate limiting
}
```

Load from config or environment:

```rust
let config = RateLimitConfig::from_env();
// or
let config: RateLimitConfig = app_config.section_or_default("rate_limit");
```

### Key Extraction

The rate limit key determines who gets throttled. Built-in extractors:

```rust
// By authenticated client identity (from RateLimitSubject)
let key_extractor = RateLimitKeyExtractor::new(ClientIdKey);

// By client IP address (from ConnectInfo)
let key_extractor = RateLimitKeyExtractor::new(IpAddressKey);
```

Custom extractors implement `RateLimitKey`:

```rust
pub trait RateLimitKey: Send + Sync + 'static {
    fn extract_key(&self, parts: &http::request::Parts) -> Option<String>;
}
```

Return `None` to skip rate limiting for a request.

### Memory Management

The Governor DashMap backing the rate limiter is periodically cleaned. A background task calls `retain_recent()` every 60 seconds to evict expired entries and prevent unbounded memory growth under attack.

## Middleware Ordering Guarantees

Multiple plugins can contribute layers to the same slot. Within a single slot, layers are ordered by plugin topological order (the order plugins appear after sorting). Across slots, the slot number determines order.

If precise ordering within a slot matters, use plugin ordering constraints:

```rust
fn ordering(&self) -> PluginOrdering {
    PluginOrdering {
        after: vec!["other-plugin"],
        ..Default::default()
    }
}
```

## Further Reading

- [Architecture](architecture.md) -- pipeline overview
- [Plugin Guide](plugin-guide.md) -- contributing layers from plugins
- [Observability](observability.md) -- logging middleware internals
- [Authentication](authentication.md) -- auth middleware
- [Database](database.md) -- transaction middleware
