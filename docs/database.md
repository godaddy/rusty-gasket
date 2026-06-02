# Database

SQLx-based database integration with PostgreSQL and MySQL support, per-request transactions, and request ID correlation for query log tracing.

## Overview

Enable `rusty-gasket` with the `db-postgres` or `db-mysql` feature to use:

- **`DatabasePlugin`** -- lifecycle plugin that manages the connection pool
- **`DbTx`** -- axum extractor for per-request transactions
- **Transaction middleware** -- begins a tracked transaction with request ID correlation
- **Auto-detection** -- PostgreSQL or MySQL determined from the connection URL scheme

## DatabasePlugin Lifecycle

`DatabasePlugin` manages the connection pool across the application lifecycle:

1. **prepare()** -- reads config, installs SQLx drivers, creates the pool, stores it in extensions
2. **shutdown()** -- closes the pool gracefully

```rust
use rusty_gasket::db::DatabasePlugin;

let app = GasketApp::builder()
    .preset(presets::api())
    .plugin(DatabasePlugin)
    .plugin(MyAppPlugin)
    .config(config)
    .build()
    .await?;
```

The plugin orders itself `before: ["gasket:server"]` so the pool is ready before the server starts accepting traffic.

### What prepare() Does

1. Reads `DatabaseConfig` from the `"database"` config section, or falls back to environment variables
2. Resolves the backend (Postgres or MySQL) from the URL scheme or explicit config
3. Calls `sqlx::any::install_default_drivers()` for the `Any` pool
4. Creates the connection pool with configured limits
5. Stores both the `AnyPool` and `ResolvedBackend` in shared extensions

### What shutdown() Does

Calls `pool.close().await` to drain active connections and prevent new ones from being acquired.

## Configuration

### Via gasket.toml

```toml
[database]
url = "postgres://user:password@localhost:5432/mydb"
backend = "auto"          # "auto", "postgres", or "mysql"
max_connections = 10
min_connections = 0
run_migrations = true
```

### Via Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | Connection string (`postgres://` or `mysql://`) |
| `DB_BACKEND` | `auto` | `"postgres"`, `"mysql"`, or `"auto"` |
| `DB_MAX_CONNECTIONS` | `10` | Maximum pool size |
| `DB_MIN_CONNECTIONS` | `0` | Minimum idle connections |
| `DB_RUN_MIGRATIONS` | `true` | Run migrations on startup |

Environment variables are the fallback when no `[database]` section exists in the config file.

### DatabaseConfig

```rust
pub struct DatabaseConfig {
    pub url: String,                  // connection URL (not serialized for safety)
    pub backend: DatabaseBackend,     // Auto, Postgres, or MySql
    pub max_connections: u32,         // default: 10
    pub min_connections: u32,         // default: 0
    pub run_migrations: bool,         // default: true
}
```

Build from env vars directly:

```rust
let config = DatabaseConfig::from_env()?;
```

## PostgreSQL vs MySQL Auto-Detection

The backend is determined from the URL scheme when `backend` is `Auto` (the default):

| URL prefix | Detected backend |
|------------|-----------------|
| `postgres://` | PostgreSQL |
| `postgresql://` | PostgreSQL |
| `mysql://` | MySQL |
| Other | Error |

You can force a specific backend regardless of URL scheme:

```toml
[database]
url = "postgres://localhost/mydb"
backend = "postgres"
```

## DbTx Extractor

`DbTx` is an axum extractor that takes ownership of the per-request database transaction:

```rust
use rusty_gasket::db::DbTx;

async fn create_item(mut tx: DbTx) -> impl IntoResponse {
    sqlx::query("INSERT INTO items (name) VALUES ($1)")
        .bind("widget")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    StatusCode::CREATED
}
```

### Key behaviors

- **One per request.** The transaction is stored in request extensions via `Arc<Mutex<Option<...>>>`. The first extractor call takes it; subsequent calls get `DbTxNotAvailable`.
- **Auto-rollback.** If `DbTx` is dropped without calling `commit()`, SQLx automatically rolls back the transaction. This is the safe default for error paths.
- **Works with both backends.** Uses SQLx's `Any` driver, so the same handler code works with PostgreSQL and MySQL.

### Commit

```rust
async fn handler(mut tx: DbTx) -> Result<impl IntoResponse, MyError> {
    sqlx::query("INSERT INTO items (name) VALUES ($1)")
        .bind("widget")
        .execute(&mut *tx)
        .await?;

    // Explicit commit -- if this line is not reached (e.g., due to ?),
    // the transaction is automatically rolled back on drop.
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}
```

### Deref

`DbTx` implements `Deref<Target = Transaction<'static, Any>>` and `DerefMut`, so you can use `&mut *tx` wherever SQLx expects a connection.

## Request ID Correlation

Each transaction sets a database session variable so slow query logs can be traced back to specific HTTP requests:

- **PostgreSQL**: `SELECT set_config('application_name', $1, true)` -- visible in `pg_stat_activity`
- **MySQL**: `SET @gasket_request_id = ?` -- available as a session variable

The value is `gasket|{request_id}` with the request ID sanitized to alphanumeric characters and dashes, truncated to 55 characters.

### Tracing a Slow Query

1. Find the slow query in your database logs -- it will show `application_name = 'gasket|abc123...'`
2. Search your application logs for `request_id = "abc123..."`
3. The log entry includes the HTTP method, path, client ID, and timing

## Transaction Middleware

The transaction middleware begins a tracked transaction for each request and stores it in request extensions:

```rust
use rusty_gasket::db::{TransactionMiddlewareState, transaction_middleware};

let state = Arc::new(TransactionMiddlewareState {
    pool: pool.clone(),
    backend: ResolvedBackend::Postgres,
});

// Applied via TaggedLayer at the Transaction slot
TaggedLayer::new(
    MiddlewareSlot::Transaction,
    move |router: Router| {
        router.layer(axum::middleware::from_fn_with_state(state, transaction_middleware))
    },
)
```

The middleware is placed in the `Transaction` slot (after auth, after rate limiting) so that rejected requests do not consume database connections.

If the transaction cannot be started (pool exhausted, database down), the middleware returns 503 Service Unavailable.

## Testing with Testcontainers

For integration tests that need a real database, use testcontainers to spin up a temporary PostgreSQL or MySQL instance:

```rust
use testcontainers::{GenericImage, runners::AsyncRunner};
use sqlx::AnyPool;

#[tokio::test]
async fn test_with_real_db() {
    let container = GenericImage::new("postgres", "16-alpine")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "testdb")
        .start()
        .await
        .expect("start postgres container");

    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:test@127.0.0.1:{port}/testdb");

    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&url).await.expect("connect");

    // Run your test queries against `pool`
    sqlx::query("CREATE TABLE test (id INT)")
        .execute(&pool)
        .await
        .expect("create table");
}
```

Add testcontainers to your dev-dependencies:

```toml
[dev-dependencies]
testcontainers = "0.23"
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `postgres` | Yes | PostgreSQL support via SQLx |
| `mysql` | No | MySQL support via SQLx |

Both can be enabled simultaneously. The `Any` driver selects the backend at runtime based on the connection URL.

## Further Reading

- [Configuration](configuration.md) -- config file format and env vars
- [Middleware](middleware.md) -- how transaction middleware fits in the pipeline
- [Testing](testing.md) -- container-backed test patterns
