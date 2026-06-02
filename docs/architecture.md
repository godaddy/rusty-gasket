# Architecture

Concise overview of Rusty Gasket's design -- plugin lifecycle, middleware pipeline, route groups, and crate layout. See [DESIGN.md](../DESIGN.md) for full rationale.

Rusty Gasket deliberately balances two goals: modern, expert-defensible Rust internally, and generated API code that backend engineers can read comfortably even if they are not experienced Rust developers.

The intended workflow is agentic code generation with human ownership. An engineer who understands the service domain should be able to ask an agent to create or modify routes, handlers, plugins, auth behavior, and configuration, then inspect the resulting Rust code with enough confidence to review it, operate it, and debug it in production.

That audience shapes the architecture. Public examples avoid boxed futures, dyn-trait ceremony, lifetime-heavy signatures, and short lifetime names unless those details are the actual topic. Internals can use advanced Rust, but the advanced pieces should sit behind named framework concepts such as `PluginHandle`, `AuthBackendHandle`, and `RouterTransform`.

## Workspace Layout

```
rusty-gasket/             # The framework crate: plugins, config, error handling,
                          #   server, health, observability, rate limiting, OpenAPI,
                          #   caching, plus optional batteries (auth, aws, db,
                          #   dynamodb, testing) as feature-gated modules
rusty-gasket-macros/      # #[derive(ApiError)] proc macro — a separate crate
                          #   because Cargo requires proc-macro crates to stand alone
examples/
  sample-api/             # runnable CRUD demo
  recipe-api/             # example using the auth + testing features
  bench-api/              # criterion benchmark target
templates/
  oss/                    # cargo-generate template for new projects
```

Application code depends only on `rusty-gasket`. Optional functionality is enabled
via Cargo features, and the corresponding dependencies are pulled in *only* when the
feature is enabled — so a minimal consumer compiles none of the auth/AWS/SQL/DynamoDB
machinery. The `#[derive(ApiError)]` proc macro is the one separate published crate
(`rusty-gasket-macros`), because Cargo does not allow a proc-macro crate to live
inside a normal library crate.

A `cargo deny` policy (advisories, licenses, sources, bans) and a CI check that the
sources carry no leaked internal references guard the public surface.

## Plugin System

Plugins are the primary extension mechanism. Every subsystem -- health checks, auth, database, rate limiting -- is a plugin. Application code is also a plugin.

### The Plugin Trait

```rust
pub trait Plugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn ordering(&self) -> PluginOrdering { PluginOrdering::default() }
    fn dependencies(&self) -> Vec<&str> { Vec::new() }

    fn init(&self, _ctx: &mut InitContext) {}
    fn configure(&self, config: AppConfig) -> AppConfig { config }
    async fn prepare(&self, _ctx: &mut PrepareContext) -> Result<(), BoxError> { Ok(()) }
    async fn ready(&self, _ctx: &ReadyContext) -> Result<(), BoxError> { Ok(()) }
    async fn shutdown(&self, _ctx: &ShutdownContext) -> Result<(), BoxError> { Ok(()) }

    fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> { Vec::new() }
    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> { Vec::new() }
}
```

Every method has a default no-op so plugins only override what they need. Application plugins can implement async hooks with plain `async fn`. Internally, Rusty Gasket stores mixed plugin types behind `PluginHandle` so the runtime can keep dynamic plugin lists without exposing boxed futures in normal app code.

### Plugin Lifecycle

Plugins are registered with `GasketApp::builder()` and run through a strict lifecycle during `build()`:

```
                      GasketApp::builder()
                             |
                    +--------v---------+
                    | Validate deps    |  duplicate names, missing dependencies
                    +--------+---------+
                             |
                    +--------v---------+
                    | Topological sort |  before/after/first/last constraints
                    +--------+---------+
                             |
                    +--------v---------+
                    | init()           |  synchronous, register named actions
                    +--------+---------+
                             |
                    +--------v---------+
                    | configure()      |  waterfall: each plugin transforms config
                    +--------+---------+
                             |
                    +--------v---------+
                    | prepare()        |  async: connect DBs, warm caches
                    +--------+---------+  (rollback on failure)
                             |
                    +--------v---------+
                    | GasketApp ready  |
                    +--------+---------+
                             |
                    +--------v---------+
                    | ready()          |  server is bound and accepting traffic
                    +--------+---------+
                             |
                        (serving)
                             |
                    +--------v---------+
                    | shutdown()       |  reverse topological order
                    +------------------+
```

**Failure handling:** If any plugin's `prepare()` fails, all previously-prepared plugins receive `shutdown()` in reverse order before the error propagates. This prevents resource leaks on partial startup.

### Plugin Ordering

Plugins declare ordering via `PluginOrdering`:

```rust
pub struct PluginOrdering {
    pub before: Vec<&'static str>,   // this plugin runs before these
    pub after: Vec<&'static str>,    // this plugin runs after these
    pub first: bool,                 // earliest possible execution
    pub last: bool,                  // latest possible execution
}
```

Constraints are normalized to directed edges and topologically sorted. Cycles and references to non-existent plugins are hard errors at startup.

### Presets

Presets are functions that return `Vec<PluginHandle>` -- a bundle of commonly-used plugins:

```rust
pub fn api() -> Vec<PluginHandle> {
    vec![PluginHandle::new(HealthPlugin::default()), PluginHandle::new(ServerPlugin)]
}
```

Use `.preset(presets::api())` in the builder to register the bundle.

## Middleware Pipeline

### Slot Ordering

The middleware pipeline is divided into ordered slots. Plugins contribute layers to specific slots; the framework assembles them in slot order regardless of plugin registration order.

```rust
pub enum MiddlewareSlot {
    TransportSecurity = 0,   // CORS, HSTS, compression
    Logging           = 10,  // request ID, tracing span, duration
    Authentication    = 20,  // auth chain, identity extraction
    RateLimit         = 30,  // per-client token bucket
    Transaction       = 40,  // per-request DB transaction
    Custom            = 50,  // application middleware
}
```

This ordering is intentional:
- **Logging before Auth** -- auth failures are logged with request IDs
- **Auth before RateLimit** -- rate limiting uses the authenticated client ID
- **RateLimit before Transaction** -- rejected requests don't waste DB connections
- **Custom closest to handlers** -- application middleware runs innermost

### How Layers are Applied

Plugins tag their middleware with a slot via `TaggedLayer`:

```rust
pub struct TaggedLayer {
    pub slot: MiddlewareSlot,
    pub layer: /* framework-owned router transform */,
}
```

Application code creates layers with `TaggedLayer::new(slot, |router| router.layer(...))`. The framework owns the type-erased closure internally so plugin authors do not need to spell the concrete Tower layer type.

The server collects all layers, sorts by slot, and applies them in reverse order (outermost first, since axum's `.layer()` wraps from the outside).

### Bidirectional Middleware Communication

The logging and auth middleware communicate through a shared `LoggingContext`:

1. **Logging middleware** creates a tracing span with empty auth fields and inserts a `LoggingContext` into request extensions
2. **Auth middleware** authenticates the request and writes auth fields (`client_id`, `user_id`, `auth_method`, `auth_result`) into the `LoggingContext`
3. **After the response**, logging middleware reads the `LoggingContext` back and records the auth fields in the span

This avoids coupling the two middleware directly while ensuring auth info appears in structured logs.

## Route Groups

Routes are tagged with a group that determines which middleware applies:

| Group | Middleware | Use for |
|-------|-----------|---------|
| `Bare` | None | Liveness probes (`/livez`) |
| `Public` | Transport security + logging + request body limit | Health checks, Swagger UI |
| `Protected` | Logging + Auth + RateLimit + Transaction + Custom | Application endpoints |

The server builds three separate axum routers and merges them:

```rust
Router::new()
    .merge(bare_router)                        // no middleware
    .merge(public_router                       // logging only
        .layer(logging_middleware))
    .merge(protected_router                    // full stack
        .layer(plugin_layers_in_slot_order)
        .layer(logging_middleware))
```

This is a first-class framework concept, not ad-hoc nesting. It prevents accidental policy drift (e.g., a developer adding an unprotected endpoint that should be behind auth).

## Application State

Plugins share state through the `extensions` map (`http::Extensions`) on context structs. During `prepare()`, plugins insert typed values:

```rust
// In DatabasePlugin::prepare()
ctx.extensions.insert(pool);      // AnyPool
ctx.extensions.insert(backend);   // ResolvedBackend
```

The extensions are available to all subsequent lifecycle phases and to middleware/routes via the `LayerContext` and `RouteContext`.

## GasketApp

The built `GasketApp` holds:
- **plugins** -- sorted in topological order
- **actions** -- named async closures registered during `init()`
- **config** -- resolved `AppConfig` (after waterfall)
- **extensions** -- shared state from `prepare()`

It exposes methods to collect layers and routes from all plugins, notify plugins of ready/shutdown events, and invoke named actions.

## Feature Flags

The public `rusty-gasket` facade uses feature flags for optional subsystems:

| Feature | Default | Description |
|---------|---------|-------------|
| `json-log` | Yes | JSON structured logging |
| `health` | Yes | Health check endpoints |
| `rate-limit` | Yes | Governor rate limiting |
| `openapi` | Yes | utoipa + Swagger UI; disable with `default-features = false` |
| `cache` | Yes | `ObjectCache`, response caching, and in-process Moka backend |
| `cache-redis` | No | Redis/Valkey cache backend |
| `cache-memcached` | No | Memcached cache backend |
| `otlp` | No | OpenTelemetry OTLP export |
| `auth` | No | JWT auth backends, auth chain, middleware, and policy extractors |
| `auth-api-key` | No | API-key auth backend in addition to JWT auth |
| `db` | No | Default SQL database integration (`db-postgres`) |
| `db-postgres` | No | PostgreSQL SQLx integration |
| `db-mysql` | No | MySQL SQLx integration |
| `dynamodb` | No | DynamoDB integration |
| `testing` | No | `TestApp`, `TestResponse`, and auth test helpers |

## Further Reading

- [DESIGN.md](../DESIGN.md) -- full rationale, design alternatives, and gasket JS comparison
- [Plugin Guide](plugin-guide.md) -- how to write a plugin
- [Middleware](middleware.md) -- detailed middleware system docs
