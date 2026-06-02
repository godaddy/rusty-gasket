# API Ergonomics

Rusty Gasket optimizes for a specific production workflow: engineers who are
strong API owners, but not Rust specialists, use agentic code generation to
create and maintain Rust services. The generated code still has to be readable
enough for those engineers to review, debug, and operate.

The framework therefore hides lower-level Rust and Tower details behind named
API concepts wherever that does not create a dead end.

## Handler Inputs

Prefer Rusty Gasket extractors in generated handlers:

```rust
use axum::Json;
use rusty_gasket::prelude::*;
use rusty_gasket::auth::CurrentUser;

#[derive(Debug, serde::Deserialize)]
struct OrderPath {
    order_id: uuid::Uuid,
}

#[derive(Debug, serde::Deserialize)]
struct CreateOrder {
    customer: String,
}

impl Validate for CreateOrder {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.customer.trim().is_empty() {
            return Err(ValidationErrors::one("customer", "customer is required"));
        }
        Ok(())
    }
}

async fn create_order(
    Context(services): Context<AppServices>,
    CurrentUser(user): CurrentUser,
    key: IdempotencyKey,
    Validated(request): Validated<CreateOrder>,
) -> Json<Order> {
    let order = services.orders.create(user.subject(), key.as_str(), request).await;
    Json(order)
}

async fn read_order(
    Context(services): Context<AppServices>,
    PathParams(path): PathParams<OrderPath>,
) -> Json<Order> {
    let order = services.orders.read(path.order_id).await;
    Json(order)
}
```

These names are deliberately plain:

- `Context<AppServices>` means application services/state.
- `CurrentUser` means the authenticated caller.
- `Validated<T>` means parse JSON and reject invalid input before the handler runs.
- `PathParams<T>` and `QueryParams<T>` mean typed route/query inputs.
- `Pagination` standardizes `page`, `limit`, and `offset`.
- `IdempotencyKey` validates the standard header for mutation endpoints.

## Policy Guards

Authorization should be visible in the handler signature, not hidden in
branches inside the handler body:

```rust
use rusty_gasket::auth::{RequireScope, RequiredScope, ServiceAccount, SuperuserOnly};

struct OrdersWrite;

impl RequiredScope for OrdersWrite {
    const SCOPE: &'static str = "orders:write";
}

async fn create_order(_scope: RequireScope<OrdersWrite>) {}

async fn run_backfill(_service: ServiceAccount) {}

async fn admin_report(_superuser: SuperuserOnly) {}
```

Rust does not allow string const generics for `RequireScope<"orders:write">` on
stable Rust, so Rusty Gasket uses tiny marker types. That is more verbose than
the dream syntax, but it is stable, explicit, and does not depend on a doomed
language workaround.

## Production Middleware

Common API middleware is provided as plugins:

```rust
let app = GasketApp::builder()
    .preset(rusty_gasket::presets::api())
    .plugin(CorsPlugin::default())
    .plugin(CompressionPlugin)
    .plugin(SecureHeadersPlugin)
    .plugin(TimeoutPlugin::from_secs(30))
    .plugin(AppPlugin)
    .build()
    .await?;
```

Transport-security middleware applies to public and protected routes. Bare
routes remain bare by design so liveness probes do not depend on middleware.

## Background Jobs

Recurring background work uses `SchedulerPlugin`:

```rust
let app = GasketApp::builder()
    .plugin(
        SchedulerPlugin::new().every("orders:expire", seconds(60), || async {
            expire_old_orders().await?;
            Ok(())
        }),
    )
    .plugin(AppPlugin)
    .build()
    .await?;
```

The closure style is intentional: generated application code can use ordinary
async blocks, while Rusty Gasket keeps task handles and boxed futures internal.

## Caching

Use `ObjectCache` for arbitrary typed data:

```rust
async fn read_product(
    Context(services): Context<AppServices>,
    PathParams(path): PathParams<ProductPath>,
) -> Result<Json<Product>, BoxError> {
    let product = services
        .cache
        .get_or_load(
            CacheKey::new("products").part(path.product_id),
            CacheTtl::minutes(5),
            async || services.products.read(path.product_id).await,
        )
        .await?;

    Ok(Json(product))
}
```

Use `route_cache_get!` when the whole response can be cached:

```rust
Router::new().route(
    "/status",
    route_cache_get!(
        cache = services.cache.clone(),
        ttl = CacheTtl::seconds(10),
        handler = status
    ),
)
```

Both forms compile down to the same framework cache APIs. The macro exists so
generated route tables can say "cache this GET response" without exposing
Tower middleware types or backend clients. The default backend is an
in-process Moka cache; Redis and Memcached are available behind feature flags.

## OpenAPI

The `openapi` feature is enabled by default because Rusty Gasket is API-first.
Keep `utoipa` path annotations next to handlers and let the plugin build from
the API document type:

```rust
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_order, read_order), components(schemas(Order)))]
struct ApiDoc;

let app = GasketApp::builder()
    .plugin(OpenApiPlugin::from_api_doc::<ApiDoc>())
    .plugin(AppPlugin)
    .build()
    .await?;
```

This keeps route behavior and route documentation close together while staying
inside `utoipa`'s stable ecosystem instead of inventing a fragile OpenAPI macro.
Minimal consumers can opt out with `default-features = false`.

## Generation

Install the generator binary and create a starter endpoint:

```bash
cargo install --path crates/cargo-gasket
cargo gasket generate endpoint orders --crud --protected --openapi --tests
```

The generator writes readable endpoint and test files, then tells you what to
wire into your app. It does not rewrite arbitrary route registries yet; that is
intentional until project layout conventions are fully stable.
