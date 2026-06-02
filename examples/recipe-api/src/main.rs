//! Run the friendly recipe API.
//!
//! Try the public endpoints first:
//! - `GET /status`
//! - `GET /v1/strings/upper?text=hello`
//!
//! Protected endpoints intentionally require auth middleware. See the tests
//! for the smallest mock-auth setup used by normal application code.

use rusty_gasket::config::{AppConfigDefinition, Environment, ServerConfig};
use rusty_gasket::plugin::GasketApp;
use rusty_gasket::presets;
use rusty_gasket::server::ServerPlugin;

use recipe_api::RecipePlugin;

#[tokio::main]
async fn main() -> Result<(), rusty_gasket::BoxError> {
    rusty_gasket::observability::init_tracing(Environment::Local);

    let config =
        AppConfigDefinition::new("recipe-api").server(ServerConfig::new("127.0.0.1", 8081));

    let app = GasketApp::builder()
        .preset(presets::api())
        .plugin(RecipePlugin)
        .config(config)
        .build()
        .await?;

    ServerPlugin::run(std::sync::Arc::new(app)).await
}
