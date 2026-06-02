//! Built-in plugin presets that bundle commonly-used plugins together.

use crate::health::HealthPlugin;
use crate::plugin::PluginHandle;
use crate::server::ServerPlugin;

/// Minimal API preset.
///
/// Bundles:
/// - [`HealthPlugin`] — `/healthcheck` aggregator and `/livez` probe
/// - [`ServerPlugin`] — HTTP/TLS server with graceful shutdown
///
/// Not included (add as needed):
/// - authentication / authorization (`rusty-gasket-auth`)
/// - rate limiting (`rusty_gasket::rate_limit`)
/// - database transactions (`rusty-gasket-db`)
/// - `OpenAPI` / Swagger UI (`openapi` feature)
/// - `DynamoDB` (`rusty-gasket-dynamodb`)
#[must_use]
pub fn api() -> Vec<PluginHandle> {
    vec![
        PluginHandle::new(HealthPlugin::default()),
        PluginHandle::new(ServerPlugin),
    ]
}
