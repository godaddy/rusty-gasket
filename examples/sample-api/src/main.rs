//! Sample API demonstrating Rusty Gasket usage.
//!
//! Run with: `cargo run -p sample-api`
//! Then visit: <http://localhost:8080/healthcheck>

use rusty_gasket::config::AppConfigDefinition;
use rusty_gasket::plugin::GasketApp;
use rusty_gasket::presets;
use rusty_gasket::server::ServerPlugin;
use sample_api::AppPlugin;

#[tokio::main]
async fn main() -> Result<(), rusty_gasket::BoxError> {
    // Initialize tracing for local development
    rusty_gasket::observability::init_tracing(rusty_gasket::config::Environment::Local);

    let config = AppConfigDefinition::new("sample-api")
        .server(rusty_gasket::config::ServerConfig::new("127.0.0.1", 8080));

    let app = GasketApp::builder()
        .preset(presets::api())
        .plugin(AppPlugin)
        .config(config)
        .build()
        .await?;

    ServerPlugin::run(std::sync::Arc::new(app)).await
}
