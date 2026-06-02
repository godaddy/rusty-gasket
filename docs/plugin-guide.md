# Plugin Guide

How to write, configure, and compose plugins in Rusty Gasket.

## Overview

Plugins are the primary extension mechanism. Every capability -- health checks, auth, database, rate limiting, and your application logic -- is a plugin. A plugin implements the `Plugin` trait and participates in the application lifecycle.

This guide is written for engineers who may be experienced backend developers but not experienced Rust developers. Rusty Gasket expects agentic tools to generate much of the plugin and handler code; the generated code still needs to be readable enough for those engineers to review, change, and support.

The framework is intentionally optimized for readable generated API code. Implement plugin hooks with ordinary `async fn` methods; Rusty Gasket keeps boxed futures and dynamic dispatch inside framework adapters. When you see `ctx`, it is the lifecycle context for that phase, not a Rust ownership trick.

## The Plugin Trait

```rust
use rusty_gasket::prelude::*;

pub trait Plugin: Send + Sync + 'static {
    /// Required: unique name for diagnostics and ordering references.
    fn name(&self) -> &'static str;

    /// Optional: ordering constraints relative to other plugins.
    fn ordering(&self) -> PluginOrdering { PluginOrdering::default() }

    /// Optional: hard dependencies (build fails if missing).
    fn dependencies(&self) -> Vec<&str> { Vec::new() }

    /// Synchronous init: register named actions.
    fn init(&self, _ctx: &mut InitContext) {}

    /// Config waterfall: transform the resolved config.
    fn configure(&self, config: AppConfig) -> AppConfig { config }

    /// Async prepare: connect to databases, warm caches.
    async fn prepare(&self, _ctx: &mut PrepareContext) -> Result<(), BoxError> { Ok(()) }

    /// Server is bound and accepting traffic.
    async fn ready(&self, _ctx: &ReadyContext) -> Result<(), BoxError> { Ok(()) }

    /// Graceful shutdown (runs in reverse plugin order).
    async fn shutdown(&self, _ctx: &ShutdownContext) -> Result<(), BoxError> { Ok(()) }

    /// Contribute middleware layers tagged with pipeline slots.
    fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> { Vec::new() }

    /// Contribute routes tagged with route groups.
    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> { Vec::new() }
}
```

Each method has a default no-op. Override only the phases your plugin needs. Async hooks are shown as `async fn` because that is the form application developers should read and write. The framework performs the object-safety boxing internally.

## Lifecycle Methods Explained

### name()

Returns a unique identifier for the plugin. Used in log messages, ordering constraints, and dependency declarations. Must be unique across all registered plugins -- duplicate names are a hard error at startup.

Convention: use `"domain:component"` names for framework plugins (`"gasket:health"`, `"gasket:server"`) and `"app"` or `"app:feature"` for application plugins.

```rust
fn name(&self) -> &'static str { "my-app:users" }
```

### ordering()

Declares when this plugin should run relative to others:

```rust
fn ordering(&self) -> PluginOrdering {
    PluginOrdering {
        before: vec!["gasket:server"],  // run before server starts
        after: vec!["gasket:health"],   // run after health is set up
        first: false,                   // not earliest
        last: false,                    // not latest
    }
}
```

Constraints:
- `before` -- this plugin must run before the named plugins
- `after` -- this plugin must run after the named plugins
- `first` -- request earliest possible execution
- `last` -- request latest possible execution

You cannot set both `first` and `last` on the same plugin. References to non-existent plugins are a hard error (unlike JS gasket which silently ignores them).

### dependencies()

Declares hard dependencies. If any named plugin is missing, `build()` returns an error immediately.

```rust
fn dependencies(&self) -> Vec<&str> {
    vec!["gasket:database"]  // requires DatabasePlugin
}
```

### init()

Synchronous. Called once during `GasketApp::builder().build()`. Use this to register named actions -- async closures that can be invoked by name at runtime.

```rust
fn init(&self, ctx: &mut InitContext) {
    ctx.register_action_fn("my-action", async |_args| {
        Ok("action result".to_string())
    })
        .expect("register action");
}
```

Duplicate action names are a hard error to prevent silent collisions.

### configure()

Synchronous waterfall. Each plugin receives the config from the previous plugin (or the initial resolved config) and returns a potentially modified version. Use this to set defaults, inject sections, or validate configuration.

```rust
fn configure(&self, mut config: AppConfig) -> AppConfig {
    if !config.has_section("my_plugin") {
        config.set_section(
            "my_plugin",
            serde_json::json!({"enabled": true, "timeout_ms": 5000}),
        );
    }
    config
}
```

### prepare()

Async. This is where plugins do their heavy initialization: connect to databases, warm caches, create HTTP clients. The `PrepareContext` provides access to the resolved config and a shared extension map.

```rust
async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
    let config: MyPluginConfig = ctx.config.section("my_plugin")?;
    let client = MyClient::connect(&config.endpoint).await?;
    ctx.extensions.insert(client);
    Ok(())
}
```

If `prepare()` fails, all previously-prepared plugins receive `shutdown()` in reverse order before the error propagates. This prevents resource leaks on partial startup.

### ready()

Async. Called after the server is bound and about to accept traffic. The context includes the local socket address.

```rust
async fn ready(&self, ctx: &ReadyContext) -> Result<(), BoxError> {
    tracing::info!(addr = %ctx.local_addr, "My plugin is ready");
    Ok(())
}
```

### shutdown()

Async. Called during graceful shutdown or after a `prepare()` failure. Plugins receive `shutdown()` in reverse topological order. Errors are logged but do not abort the shutdown sequence.

```rust
async fn shutdown(&self, ctx: &ShutdownContext) -> Result<(), BoxError> {
    if let Some(client) = ctx.extensions.get::<MyClient>() {
        client.close().await;
    }
    Ok(())
}
```

## Contributing Routes

Plugins contribute routes via the `routes()` method. Each route is tagged with a `RouteGroup` that determines which middleware applies:

```rust
fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
    let api_routes = Router::new()
        .route("/v1/users", get(list_users).post(create_user))
        .route("/v1/users/{id}", get(get_user).delete(delete_user));

    vec![TaggedRoute::new(RouteGroup::Protected, api_routes)]
}
```

Route groups:
- `RouteGroup::Bare` -- no middleware (liveness probes)
- `RouteGroup::Public` -- logging middleware only (health checks, Swagger UI)
- `RouteGroup::Protected` -- full middleware stack (auth, rate limiting, transactions)

You can return multiple `TaggedRoute` entries with different groups:

```rust
fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
    vec![
        TaggedRoute::new(
            RouteGroup::Bare,
            Router::new().route("/livez", get(|| async { StatusCode::OK })),
        ),
        TaggedRoute::new(
            RouteGroup::Protected,
            Router::new().route("/v1/data", get(get_data)),
        ),
    ]
}
```

### Routes with State

If your handlers need shared state, use axum's `with_state()`:

```rust
fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
    let store = ItemStore::default();

    let router = Router::new()
        .route("/v1/items", get(list_items).post(create_item))
        .with_state(store);

    vec![TaggedRoute::new(RouteGroup::Protected, router)]
}
```

### Routes Using Shared Extensions

If your plugin stored state in `ctx.extensions` during `prepare()`, access it from the `RouteContext`:

```rust
fn routes(&self, ctx: &RouteContext) -> Vec<TaggedRoute> {
    let pool = ctx.extensions.get::<AnyPool>()
        .expect("database pool should be in extensions")
        .clone();

    let router = Router::new()
        .route("/v1/data", get(get_data))
        .with_state(pool);

    vec![TaggedRoute::new(RouteGroup::Protected, router)]
}
```

## Contributing Middleware

Plugins contribute middleware layers via the `layers()` method. Each layer is tagged with a `MiddlewareSlot` that determines its position in the pipeline:

```rust
use rusty_gasket::pipeline::MiddlewareSlot;

fn layers(&self, ctx: &LayerContext) -> Vec<TaggedLayer> {
    let my_state = Arc::new(MyMiddlewareState { /* ... */ });

    vec![TaggedLayer::new(
        MiddlewareSlot::Custom,
        move |router: Router| {
            router.layer(axum::middleware::from_fn_with_state(
                my_state,
                my_middleware_fn,
            ))
        },
    )]
}
```

`TaggedLayer::new` hides the closure type used to wrap middleware around a router. See [middleware.md](middleware.md) for the full middleware system.

## Contributing Health Checks

Implement the `HealthContributor` trait and register it with `HealthPlugin`:

```rust
use rusty_gasket::health::{HealthContributor, HealthStatus};

struct DatabaseHealthCheck {
    pool: AnyPool,
}

impl HealthContributor for DatabaseHealthCheck {
    fn name(&self) -> &'static str { "database" }

    async fn check(&self) -> HealthStatus {
        match sqlx::query("SELECT 1").execute(&self.pool).await {
            Ok(_) => HealthStatus::Healthy,
            Err(_) => HealthStatus::Error,
        }
    }
}
```

Register it by mutating the `HealthPlugin` before passing it to the builder:

```rust
let mut health = HealthPlugin::default();
health.add_contributor(DatabaseHealthCheck { pool: pool.clone() });

let app = GasketApp::builder()
    .plugin(health)
    .plugin(MyAppPlugin)
    .build()
    .await?;
```

## Config Waterfall

The configuration flows through plugins in topological order:

1. `AppConfigDefinition` is loaded from TOML/YAML or built in code
2. `resolve()` detects the environment and applies per-env overrides
3. Each plugin's `configure()` receives and returns the `AppConfig`

Plugins typically use `configure()` to set defaults for their own config section:

```rust
fn configure(&self, mut config: AppConfig) -> AppConfig {
    if !config.has_section("rate_limit") {
        config.set_section("rate_limit", serde_json::json!({
            "enabled": true,
            "requests_per_minute": 60,
            "burst_size": 10,
        }));
    }
    config
}
```

Then in `prepare()`, read the config:

```rust
async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
    let config: RateLimitConfig = ctx.config.section_or_default("rate_limit")?;
    // ...
    Ok(())
}
```

`section_or_default()` returns `T::default()` if the section is missing. `section()` returns an error.

## Full Worked Example

A complete plugin that adds a simple metrics endpoint, contributes a health check, and sets configuration defaults:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::routing::get;
use axum::{Json, Router};

use rusty_gasket::prelude::*;
use rusty_gasket::health::{HealthContributor, HealthStatus};

/// Shared state for the metrics plugin.
#[derive(Debug, Default)]
struct MetricsState {
    request_count: AtomicU64,
}

/// Health check that reports healthy if the service has handled requests.
struct MetricsHealthCheck {
    state: Arc<MetricsState>,
}

impl HealthContributor for MetricsHealthCheck {
    fn name(&self) -> &'static str { "metrics" }

    async fn check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

/// Plugin that tracks request counts and exposes them.
#[derive(Debug)]
pub struct MetricsPlugin;

impl Plugin for MetricsPlugin {
    fn name(&self) -> &'static str { "app:metrics" }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering {
            after: vec!["gasket:health"],
            before: vec!["gasket:server"],
            ..Default::default()
        }
    }

    fn configure(&self, mut config: AppConfig) -> AppConfig {
        if !config.has_section("metrics") {
            config.set_section("metrics", serde_json::json!({
                "enabled": true,
            }));
        }
        config
    }

    async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
        let state = Arc::new(MetricsState::default());
        ctx.extensions.insert(state);
        Ok(())
    }

    fn routes(&self, ctx: &RouteContext) -> Vec<TaggedRoute> {
        let state = ctx.extensions.get::<Arc<MetricsState>>()
            .cloned()
            .unwrap_or_default();

        let router = Router::new()
            .route("/metrics", get({
                let s = state.clone();
                move || {
                    let count = s.request_count.load(Ordering::Relaxed);
                    async move {
                        Json(serde_json::json!({"request_count": count}))
                    }
                }
            }));

        vec![TaggedRoute::new(RouteGroup::Public, router)]
    }

    async fn shutdown(&self, _ctx: &ShutdownContext) -> Result<(), BoxError> {
        tracing::info!("Metrics plugin shutting down");
        Ok(())
    }
}
```

Register it in your application:

```rust
let app = GasketApp::builder()
    .preset(presets::api())
    .plugin(MetricsPlugin)
    .plugin(MyAppPlugin)
    .build()
    .await?;
```

## Tips

- Keep plugins focused. Split large feature areas into separate plugins.
- Use `ordering()` to declare relationships. Do not rely on registration order.
- Store shared state in `ctx.extensions` during `prepare()` for other plugins and routes to access.
- Use `dependencies()` to fail fast if a required plugin is missing.
- Plugin names must be unique. The builder rejects duplicates at startup.

## Further Reading

- [Architecture](architecture.md) -- overall framework design
- [Middleware](middleware.md) -- pipeline slots and custom middleware
- [Configuration](configuration.md) -- config waterfall and env overrides
