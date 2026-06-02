<p align="center">
  <img alt="Rusty Gasket" src="/docs/images/rusty-gasket.svg" width="496" />
</p>

<p align="center">
Framework for Rust API Services
</p>

---

A plugin-based Rust framework for backend HTTP services. The architecture — lifecycle phases, plugin composition, and route groups with stacked middleware — is borrowed from [GoDaddy's Gasket](https://github.com/godaddy/gasket), which targets full-stack JavaScript apps and pairs a Node backend with a React frontend. Rusty Gasket adapts the same lifecycle-driven plugin model for Rust backends only; the frontend half of the analogy is out of scope.

Build production HTTP APIs with a lifecycle-driven plugin system, pluggable middleware pipeline, and clean separation between open-source core and organization-specific overlays.

Rusty Gasket is designed for teams that want Rust's deployment, runtime, and safety benefits without requiring every API owner to become a Rust specialist first. The primary use case is agentic code generation: a software engineer describes or evolves an API, an agent generates the Rust implementation, and the engineer still needs to read, review, debug, and maintain that code in production.

That means generated application code must be approachable to engineers who are experienced in backend systems but new to Rust. The framework uses modern Rust internally, but keeps boxing, object-safety adapters, lifetime-heavy signatures, and ownership-heavy syntax behind named framework types wherever practical.

Readability is part of the framework contract. Public APIs, framework handles,
and non-obvious internal adapters should be documented in domain language so
developers can understand the code without first decoding Rust's lower-level
type machinery.

## Design Priorities

1. **Readable generated APIs** -- route handlers, plugins, auth backends, and configuration should look like ordinary service code.
2. **Modern Rust under the hood** -- advanced Rust is allowed inside the framework when it buys safety, correctness, or performance, but it should be wrapped in named concepts.
3. **Production ownership by non-Rust specialists** -- comments, rustdoc, examples, and type names should help backend engineers understand generated code well enough to operate it.
4. **Expert-defensible tradeoffs** -- novice ergonomics matter most, but not by committing to obsolete patterns, unsound shortcuts, or dead-end abstractions.

## Quick Start

```rust
use axum::{Json, Router, routing::get};
use rusty_gasket::prelude::*;
use serde::{Deserialize, Serialize};

// A plugin is the unit of API composition.
// It can contribute routes, middleware, config changes, health checks,
// and startup/shutdown work.
#[derive(Debug)]
struct MathPlugin;

// Request inputs are ordinary typed structs.
// Serde fills this from query parameters: /v1/add?a=2&b=3
#[derive(Deserialize)]
struct AddQuery {
    a: f64,
    b: f64,
}

// Response bodies are ordinary typed structs too.
// Serde turns this into JSON for the HTTP response.
#[derive(Serialize)]
struct AddResponse {
    a: f64,
    b: f64,
    sum: f64,
}

// A second request type for a string-processing endpoint.
// Example: /v1/upper?text=hello
#[derive(Deserialize)]
struct UpperQuery {
    text: String,
}

#[derive(Serialize)]
struct UpperResponse {
    original: String,
    upper: String,
}

// Public endpoints can return small status payloads without requiring auth.
#[derive(Serialize)]
struct StatusResponse {
    service: &'static str,
    status: &'static str,
}

impl Plugin for MathPlugin {
    // Stable plugin names are used in logs, startup ordering, and diagnostics.
    fn name(&self) -> &'static str {
        "math"
    }

    // Register this plugin's HTTP routes.
    //
    // Routes are grouped by the middleware they should receive.
    //
    // RouteGroup::Public is for unauthenticated endpoints such as status,
    // documentation, or public metadata. It still receives request logging
    // and body limits.
    //
    // RouteGroup::Protected is for normal API functionality. It receives
    // the full production middleware stack: request logging, body limits,
    // auth, rate limiting, transactions, and any application middleware.
    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        let public_routes = Router::new().route("/status", get(status));

        let protected_routes = Router::new()
            .route("/v1/add", get(add_numbers))
            .route("/v1/upper", get(to_uppercase));

        vec![
            TaggedRoute::new(RouteGroup::Public, public_routes),
            TaggedRoute::new(RouteGroup::Protected, protected_routes),
        ]
    }
}

// Handlers are just async functions.
// No boxed futures, no lifetime annotations, no framework-specific ceremony.
async fn add_numbers(QueryParams(query): QueryParams<AddQuery>) -> Json<AddResponse> {
    Json(AddResponse {
        a: query.a,
        b: query.b,
        sum: query.a + query.b,
    })
}

async fn to_uppercase(QueryParams(query): QueryParams<UpperQuery>) -> Json<UpperResponse> {
    Json(UpperResponse {
        upper: query.text.to_uppercase(),
        original: query.text,
    })
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        service: "my-api",
        status: "ok",
    })
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Initialize structured logging (pretty locally, JSON in production).
    rusty_gasket::observability::init_tracing(Environment::Local);

    // Load gasket.toml if it exists; fall back to in-code defaults if
    // the file is missing. Parse errors are propagated.
    let config = AppConfigDefinition::from_file_optional("gasket.toml")?
        .unwrap_or_else(|| AppConfigDefinition::new("my-api"));

    // Build the app through the plugin lifecycle:
    // init -> configure -> prepare. The server will call ready after binding.
    let app = GasketApp::builder()
        // Bundles the framework's health and server plugins.
        .preset(rusty_gasket::presets::api())
        // Production API middleware with readable plugin names.
        .plugin(CorsPlugin::default())
        .plugin(CompressionPlugin)
        .plugin(SecureHeadersPlugin)
        .plugin(TimeoutPlugin::from_secs(30))
        // Adds this API's routes.
        .plugin(MathPlugin)
        .config(config)
        .build()
        .await?;

    // Start the server. Blocks until SIGTERM or Ctrl+C, then shuts down gracefully.
    ServerPlugin::run(std::sync::Arc::new(app)).await
}
```

```bash
cargo run
curl "http://localhost:8443/status"                 # unauthenticated
curl "http://localhost:8443/v1/add?a=2&b=3"         # protected
curl "http://localhost:8443/v1/upper?text=hello"    # protected
curl "http://localhost:8443/healthcheck"            # built-in health endpoint
```

> **Swagger UI**: The `openapi` feature is enabled by default for API projects.
> Add `OpenApiPlugin` to serve interactive API docs at `/swagger-ui/`. Minimal
> consumers can opt out with `default-features = false`.

## Crates

| Crate | Description |
|-------|-------------|
| `rusty-gasket` | The framework: plugins, config, error handling, server, health, observability, rate limiting, OpenAPI, and caching — plus optional batteries (auth, AWS, SQL via `db`, DynamoDB, testing) behind feature flags. |
| `rusty-gasket-macros` | `#[derive(ApiError)]` proc macro for ergonomic error types. |

Application code depends only on `rusty-gasket`; optional functionality is turned on with feature flags (see below).

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first project, first route |
| [API Ergonomics](docs/api-ergonomics.md) | Novice-readable handlers, policy guards, context, generators, OpenAPI |
| [Architecture](docs/architecture.md) | Plugin lifecycle, middleware pipeline, route groups |
| [Plugin Guide](docs/plugin-guide.md) | Writing plugins: ordering, routes, layers, health |
| [Authentication](docs/authentication.md) | JWT, API keys, auth chain, extractors, policies |
| [Database](docs/database.md) | SQLx, transactions, request ID correlation |
| [Caching](docs/caching.md) | ObjectCache, response caching, Redis, Memcached |
| [Configuration](docs/configuration.md) | Config files, env vars, secrets, environments |
| [Error Handling](docs/error-handling.md) | ApiError trait, derive macro, structured errors |
| [Testing](docs/testing.md) | TestApp, mocks, containers, benchmarks |
| [Observability](docs/observability.md) | Tracing, request IDs, OpenTelemetry |
| [Middleware](docs/middleware.md) | Pipeline slots, custom middleware, route groups |
| [Changelog](CHANGELOG.md) | Release history |
| [Contributing](CONTRIBUTING.md) | Development setup, testing, PR process |

## Feature Flags

### `rusty-gasket`

| Feature | Default | Description |
|---------|---------|-------------|
| `json-log` | Yes | JSON structured logging |
| `health` | Yes | Health check endpoints |
| `rate-limit` | Yes | Governor rate limiting |
| `openapi` | Yes | utoipa + Swagger UI at `/swagger-ui/`; disable with `default-features = false` |
| `cache` | Yes | ObjectCache, response caching, and in-process Moka backend |
| `cache-redis` | No | Redis/Valkey object-cache backend |
| `cache-memcached` | No | Memcached object-cache backend |
| `otlp` | No | OpenTelemetry OTLP span + metric export |
| `auth` | No | JWT auth backends, auth chain, middleware, and policy extractors |
| `auth-api-key` | No | API-key auth backend in addition to JWT auth |
| `aws` | No | AWS integration helpers |
| `db` | No | Default SQL database integration (`db-postgres`) |
| `db-postgres` | No | PostgreSQL SQLx integration, transaction middleware, `DbTx` extractor |
| `db-mysql` | No | MySQL SQLx integration, transaction middleware, `DbTx` extractor |
| `dynamodb` | No | DynamoDB lifecycle plugin and extractor |
| `testing` | No | `TestApp`, `TestResponse`, and in-process auth test helpers |

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo bench -p bench-api          # criterion benchmarks
```

### Creating a New Project

```bash
cargo generate --git https://github.com/godaddy/rusty-gasket --path templates/oss
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
