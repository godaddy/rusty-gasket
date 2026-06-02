//! Entry point for a Rusty Gasket API service.
//!
//! This template sets up a minimal production-ready HTTP API with:
//! - Health checks (`/healthcheck`, `/livez`)
//! - Structured JSON logging
//! - Plugin-based route registration
//! - Graceful shutdown on SIGTERM/Ctrl+C
//!
//! ## Running
//!
//! ```sh
//! cargo run
//! curl http://localhost:8443/healthcheck
//! curl http://localhost:8443/v1/hello
//! ```
//!
//! ## Customizing
//!
//! - Add routes in `routes.rs` via the `AppPlugin`
//! - Add config in `gasket.toml` (TOML) or `gasket.yaml` (YAML)
//! - Add plugins with `.plugin(MyPlugin)` in the builder chain

use rusty_gasket::config::AppConfigDefinition;
use rusty_gasket::plugin::GasketApp;
use rusty_gasket::presets;
use rusty_gasket::server::ServerPlugin;

mod routes;

#[tokio::main]
async fn main() -> Result<(), rusty_gasket::BoxError> {
    // Initialize structured logging. Uses pretty-print locally,
    // JSON in non-local environments. Controlled by GASKET_ENV.
    rusty_gasket::observability::init_tracing(rusty_gasket::config::Environment::Local);

    // Load config from gasket.toml (falls back to defaults if missing).
    let config = AppConfigDefinition::from_file("gasket.toml").unwrap_or_default();

    // Build the application through the plugin lifecycle:
    //   init → configure → prepare → ready
    let app = GasketApp::builder()
        // presets::api() bundles HealthPlugin + ServerPlugin
        .preset(presets::api())
        // Your application routes (see routes.rs)
        .plugin(routes::AppPlugin)
        .config(config)
        .build()
        .await?;

    // Start the HTTP server (blocks until shutdown signal)
    ServerPlugin::run(std::sync::Arc::new(app)).await
}
