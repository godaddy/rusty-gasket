//! Benchmark API server for measuring Rusty Gasket framework overhead.
//!
//! Run directly: `cargo run --release -p bench-api`
//! Run benchmarks: `cargo bench -p bench-api`
//! Load test: `scripts/load-test.sh`

use axum::Router;
use axum::routing::{get, post};

use rusty_gasket::config::AppConfigDefinition;
use rusty_gasket::plugin::{GasketApp, Plugin, RouteContext, RouteGroup, TaggedRoute};
use rusty_gasket::presets;
use rusty_gasket::server::ServerPlugin;

use bench_api::{json_echo, json_response, noop};

#[derive(Debug)]
struct BenchPlugin;

impl Plugin for BenchPlugin {
    fn name(&self) -> &'static str {
        "bench"
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        let router = Router::new()
            .route("/bench/noop", get(noop))
            .route("/bench/json", get(json_response))
            .route("/bench/echo", post(json_echo));

        vec![TaggedRoute::new(RouteGroup::Protected, router)]
    }
}

#[tokio::main]
async fn main() -> Result<(), rusty_gasket::BoxError> {
    rusty_gasket::observability::init_tracing(rusty_gasket::config::Environment::Local);

    let config = AppConfigDefinition::new("bench-api")
        .server(rusty_gasket::config::ServerConfig::new("127.0.0.1", 8081));

    let app = GasketApp::builder()
        .preset(presets::api())
        .plugin(BenchPlugin)
        .config(config)
        .build()
        .await?;

    ServerPlugin::run(std::sync::Arc::new(app)).await
}
