//! Database integration for Rusty Gasket using `SQLx`.
//!
//! Supports `PostgreSQL` and `MySQL` via `SQLx`'s `Any` driver, which selects
//! the backend at runtime based on the connection URL scheme (`postgres://`
//! or `mysql://`).
//!
//! Enable backends via Cargo features:
//! - `postgres` (default) — `PostgreSQL` support
//! - `mysql` — `MySQL` support
//! - Both can be enabled simultaneously
//!
//! Provides:
//! - [`DatabasePlugin`] — lifecycle plugin that manages the connection pool
//! - [`DbTx`] — axum extractor for per-request transactions
//! - Transaction middleware with request ID correlation for query log tracing
//! - Pool configuration from `AppConfig` or environment variables

// SQLx's Any driver needs at least one concrete backend registered or
// the runtime pool is silently inert. Fail at compile time so an
// operator who accidentally disabled both backends sees the problem
// before deploy.
#[cfg(not(any(feature = "db-postgres", feature = "db-mysql")))]
compile_error!(
    "rusty-gasket-db requires at least one backend feature. Enable `postgres` or `mysql` \
     (or both) in your Cargo.toml — for example:\n\n    \
     [dependencies]\n    \
     rusty-gasket-db = { version = \"0.1\", features = [\"postgres\"] }\n\n\
     Building with neither feature produces a runtime pool that registers no SQLx drivers."
);

mod config;
mod extractor;
mod plugin;
mod transaction;

pub use config::{ConfigError, DatabaseBackend, DatabaseConfig, ResolvedBackend};
pub use extractor::{DbTx, DbTxNotAvailable};
pub use plugin::DatabasePlugin;
pub use rusty_gasket::BoxError;
pub use transaction::{
    RequestTransaction, TransactionMiddlewareState, begin_tracked_transaction,
    transaction_middleware,
};

/// Re-export the pool type consumers should use. Pinned to the `SQLx`
/// major version this crate was compiled against — bumping `SQLx` is a
/// semver-major change for `rusty-gasket-db`.
pub use sqlx::AnyPool;

/// Re-exports of the most commonly used database types.
///
/// `use rusty_gasket::db::prelude::*` to get extractor and plugin in
/// one import.
pub mod prelude {
    pub use rusty_gasket::db::{
        BoxError, DatabaseConfig, DatabasePlugin, DbTx, DbTxNotAvailable, RequestTransaction,
    };
}
