# Getting Started

Get a Rusty Gasket API running locally in under five minutes.

Rusty Gasket is optimized for teams using agentic code generation to build and maintain Rust APIs. You do not need to be a Rust expert to follow the generated application code: handlers are ordinary async functions, plugins use readable lifecycle methods, and the framework hides most boxed futures, dynamic dispatch, and ownership plumbing behind named types.

The goal is not to pretend Rust has no complexity. The goal is to keep that complexity in framework code so backend engineers can confidently review, modify, and operate generated API code.

## Prerequisites

- **Rust 1.91+** (edition 2024). Install via [rustup](https://rustup.rs/).
- **Docker** (optional) -- needed for database integration tests via testcontainers.
- **just** (optional) -- task runner (`brew install just`). Not required, but simplifies common commands.

Verify your Rust version:

```bash
rustc --version   # must be >= 1.91
```

## Creating a Project from the Template

The fastest way to start is with `cargo-generate`:

```bash
cargo install cargo-generate

# Open-source project (no GoDaddy dependencies)
cargo generate --git https://github.com/godaddy/rusty-gasket --path templates/oss
```

This creates a project with:
- A `main.rs` that sets up tracing, loads config, and starts the server
- A `routes.rs` with a sample `AppPlugin` and a `/v1/hello` endpoint
- Health checks at `/healthcheck` and `/livez` out of the box
- A `gasket.toml` config file (optional -- defaults work for local dev)

## Running the Sample API

If you cloned the rusty-gasket repo directly, you can run the included sample:

```bash
cargo run -p sample-api
```

Or with just:

```bash
just run-sample
```

The server starts on `http://127.0.0.1:8080` (sample-api) or `http://127.0.0.1:8443` (default). Test it:

```bash
curl http://127.0.0.1:8080/healthcheck
curl http://127.0.0.1:8080/v1/items
curl -X POST http://127.0.0.1:8080/v1/items \
  -H 'Content-Type: application/json' \
  -d '{"name": "Widget", "description": "A useful widget"}'
```

## Minimal Application

Here is the smallest possible Rusty Gasket application:

```rust
use rusty_gasket::prelude::*;

#[derive(Debug)]
struct MyAppPlugin;

impl Plugin for MyAppPlugin {
    fn name(&self) -> &'static str { "my-app" }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        vec![TaggedRoute::new(
            RouteGroup::Protected,
            Router::new().route("/v1/hello", get(|| async { "Hello from Rusty Gasket!" })),
        )]
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    rusty_gasket::observability::init_tracing(Environment::Local);

    let app = GasketApp::builder()
        .preset(rusty_gasket::presets::api())
        .plugin(MyAppPlugin)
        .config(AppConfigDefinition::from_file("gasket.toml").unwrap_or_default())
        .build()
        .await?;

    ServerPlugin::run(std::sync::Arc::new(app)).await
}
```

The `presets::api()` preset bundles `HealthPlugin` (provides `/healthcheck` and `/livez`) and `ServerPlugin` (HTTP server with graceful shutdown). Your `MyAppPlugin` adds application routes.

## Adding Your First Route

Routes are added through plugins. Edit your plugin's `routes()` method:

```rust
use axum::Json;
use axum::http::StatusCode;
use rusty_gasket::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Item {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CreateItemRequest {
    name: String,
}

impl Validate for CreateItemRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.name.trim().is_empty() {
            return Err(ValidationErrors::one("name", "name is required"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ItemPath {
    id: String,
}

fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
    let router = Router::new()
        .route("/v1/items", get(list_items).post(create_item))
        .route("/v1/items/{id}", get(get_item));

    vec![TaggedRoute::new(RouteGroup::Protected, router)]
}

async fn list_items(pagination: Pagination) -> Json<Vec<Item>> {
    let _offset = pagination.offset();
    Json(Vec::<Item>::new())
}

async fn create_item(Validated(request): Validated<CreateItemRequest>) -> (StatusCode, Json<Item>) {
    let item = Item {
        id: uuid::Uuid::now_v7().to_string(),
        name: request.name,
    };
    (StatusCode::CREATED, Json(item))
}

async fn get_item(PathParams(path): PathParams<ItemPath>) -> Json<Item> {
    Json(Item {
        id: path.id,
        name: "placeholder".to_owned(),
    })
}
```

Routes tagged with `RouteGroup::Protected` receive the full middleware stack (logging, auth, rate limiting). Use `RouteGroup::Public` for routes that need logging but not auth, or `RouteGroup::Bare` for endpoints with no middleware at all (like liveness probes).

## Adding Configuration

Create a `gasket.toml` in your project root:

```toml
name = "my-api"

[server]
host = "127.0.0.1"
port = 8080
```

Environment-specific overrides use the `[environments]` table:

```toml
[environments.production.server]
host = "0.0.0.0"
port = 8443
```

The environment is resolved from the `GASKET_ENV` environment variable (default: `local`). See [configuration.md](configuration.md) for full details.

## Running Checks

Before pushing code:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Or with just:

```bash
just check
```

## Project Structure

A typical Rusty Gasket project looks like:

```
my-api/
  Cargo.toml
  gasket.toml           # Application config
  src/
    main.rs             # Entry point: tracing, config, builder, server
    routes.rs           # AppPlugin with route handlers
  tests/
    integration.rs      # TestApp-based integration tests
```

For larger projects, split routes across multiple plugins:

```rust
let app = GasketApp::builder()
    .preset(presets::api())
    .plugin(UsersPlugin)
    .plugin(OrdersPlugin)
    .plugin(AdminPlugin)
    .build()
    .await?;
```

## Next Steps

- [Plugin Guide](plugin-guide.md) -- writing plugins, lifecycle hooks, middleware, health checks
- [Architecture](architecture.md) -- how the framework is structured
- [Authentication](authentication.md) -- JWT, API keys, auth chains
- [Database](database.md) -- PostgreSQL/MySQL integration
- [Configuration](configuration.md) -- config files, env vars, secrets
- [Error Handling](error-handling.md) -- `#[derive(ApiError)]` and structured error responses
- [Testing](testing.md) -- `TestApp`, mock auth, container-backed tests
- [Observability](observability.md) -- logging, request IDs, OpenTelemetry
- [Middleware](middleware.md) -- pipeline slots, custom middleware
