//! Database lifecycle plugin.
//!
//! Manages the `SQLx` connection pool across the application lifecycle:
//! creates the pool during `prepare` and closes it during `shutdown`.

use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

use rusty_gasket::BoxError;
use rusty_gasket::plugin::{Plugin, PluginOrdering, PrepareContext, ShutdownContext};

use rusty_gasket::db::config::DatabaseConfig;

/// Lifecycle plugin that manages the database connection pool.
///
/// Supports `PostgreSQL` and `MySQL` via `SQLx`'s `Any` driver. The backend
/// is determined automatically from the connection URL scheme, or can
/// be set explicitly in the configuration.
///
/// During `prepare`, it reads `DatabaseConfig` from the app config's
/// `"database"` section (or falls back to environment variables),
/// installs the `SQLx` drivers, creates a connection pool, and stores
/// it in the shared extensions.
#[derive(Debug, Default)]
pub struct DatabasePlugin;

impl Plugin for DatabasePlugin {
    fn name(&self) -> &'static str {
        "gasket:database"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
        let db_config: DatabaseConfig = if ctx.config.has_section("database") {
            ctx.config.section("database")?
        } else {
            DatabaseConfig::from_env()?
        };

        let backend = db_config.backend.resolve(&db_config.url)?;

        sqlx::any::install_default_drivers();

        let pool = AnyPoolOptions::new()
            .max_connections(db_config.max_connections)
            .min_connections(db_config.min_connections)
            .acquire_timeout(std::time::Duration::from_secs(
                db_config.acquire_timeout_secs,
            ))
            .connect(&db_config.url)
            .await
            .map_err(|e| format!("Failed to connect to {backend} database: {e}"))?;

        tracing::info!(
            backend = %backend,
            max_connections = db_config.max_connections,
            "Database pool created"
        );

        ctx.extensions.insert(pool);
        ctx.extensions.insert(backend);
        Ok(())
    }

    async fn shutdown(&self, ctx: &ShutdownContext) -> Result<(), BoxError> {
        if let Some(pool) = ctx.extensions.get::<AnyPool>() {
            tracing::info!("Closing database pool");
            pool.close().await;
        }
        Ok(())
    }
}
