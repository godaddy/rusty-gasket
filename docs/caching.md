# Caching

Rusty Gasket has two cache facilities:

- `ObjectCache` stores arbitrary typed values behind readable keys.
- `cached_get` and `route_cache_get!` cache an entire GET response for a short
  period of time.

The default backend is an in-process Moka cache with a 128 MiB memory budget.
That gives local development and small services a useful cache without Redis,
Memcached, or any external setup. Redis and Memcached are supported through
feature flags for services that need shared cache state across processes.

## Object Cache

Keep an `ObjectCache` in your application services and use it from service
methods:

```rust
use rusty_gasket::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct AppServices {
    cache: ObjectCache,
    products: ProductRepository,
}

#[derive(Clone, Serialize, Deserialize)]
struct ProductSummary {
    id: String,
    name: String,
}

impl AppServices {
    async fn product_summary(&self, product_id: &str) -> Result<ProductSummary, BoxError> {
        self.cache
            .get_or_load(
                CacheKey::new("products").part(product_id).part("summary"),
                CacheTtl::minutes(5),
                async || self.products.fetch_summary(product_id).await,
            )
            .await
            .map_err(Into::into)
    }
}
```

`CacheKey` percent-encodes key parts so generated code does not need hand-built
`format!` strings. `get_or_load` coalesces concurrent misses for the same key
by default, so a cold cache entry causes one database/API load instead of a
request stampede.

## Response Cache

For read-only endpoints, cache the whole HTTP response:

```rust
use axum::{Json, Router};
use rusty_gasket::prelude::*;

#[derive(serde::Serialize)]
struct StatusResponse {
    status: &'static str,
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse { status: "ok" })
}

fn routes(cache: ObjectCache) -> Router {
    Router::new().route(
        "/status",
        route_cache_get!(
            cache = cache,
            ttl = CacheTtl::seconds(10),
            handler = status
        ),
    )
}
```

The macro expands to the explicit API:

```rust
Router::new().route(
    "/status",
    cached_get(
        cache,
        ResponseCachePolicy::public(CacheTtl::seconds(10)),
        status,
    ),
)
```

Response caching is intentionally conservative:

- only `GET` and `HEAD` are cacheable;
- only 2xx responses are stored;
- responses with `Cache-Control: no-store` or `Set-Cookie` are not stored;
- bodies larger than 2 MiB are skipped by default;
- the response includes `X-Cache: HIT`, `MISS`, or `BYPASS`;
- cache backend failures fail open and log a warning instead of breaking the API.

Use `ResponseCachePolicy::per_authorization(...)` when a response is specific
to the caller. That policy hashes the `Authorization` header into the cache key
instead of storing the raw token.

## Configuration

The default config is equivalent to:

```toml
[cache]
backend = "memory"
algorithm = "tiny-lfu"
max_memory = "128 MiB"
default_ttl = "60s"
namespace = "rusty-gasket"
single_flight = true
```

Build an object cache from config:

```rust
let cache_config = app_config.section_or_default::<CacheConfig>("cache")?;
let cache = ObjectCache::from_config(cache_config).await?;
```

Redis is available behind `cache-redis`:

```toml
[cache]
backend = "redis"
namespace = "catalog-api"

[cache.redis]
url = "redis://127.0.0.1/"
```

Memcached is available behind `cache-memcached`:

```toml
[cache]
backend = "memcached"
namespace = "catalog-api"

[cache.memcached]
servers = ["127.0.0.1:11211"]
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `cache` | Yes | `ObjectCache`, response caching, and in-process Moka backend |
| `cache-redis` | No | Redis/Valkey backend through the `redis` crate |
| `cache-memcached` | No | Memcached backend through `memcache-async` |

External cache dependencies are not pulled in unless their feature is enabled.
The core `cache` feature stays on by default because API projects commonly need
some form of short-lived cache, and the in-process backend has no infrastructure
requirement.
