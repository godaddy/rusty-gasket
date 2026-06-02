//! Batteries-included middleware plugins for common API services.
//!
//! These plugins wrap proven `tower-http` middleware in Rusty Gasket's
//! lifecycle and pipeline concepts so application authors can add production
//! defaults without learning Tower layer types first.

use std::time::Duration;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use crate::pipeline::MiddlewareSlot;
use crate::plugin::{LayerContext, Plugin, PluginOrdering, TaggedLayer};

/// CORS middleware plugin.
///
/// The default is intentionally strict and does not allow cross-origin traffic.
/// Use [`Self::permissive_for_local_development`] for local demos, or
/// [`Self::new`] with a carefully configured `CorsLayer` for production.
#[derive(Debug, Clone)]
pub struct CorsPlugin {
    layer: CorsLayer,
}

impl CorsPlugin {
    /// Create a CORS plugin from a configured `tower_http::cors::CorsLayer`.
    #[must_use]
    pub const fn new(layer: CorsLayer) -> Self {
        Self { layer }
    }

    /// Create a permissive CORS plugin for local development and examples.
    ///
    /// Avoid this in production unless every origin is intentionally allowed.
    #[must_use]
    pub fn permissive_for_local_development() -> Self {
        Self {
            layer: CorsLayer::permissive(),
        }
    }
}

impl Default for CorsPlugin {
    fn default() -> Self {
        Self {
            layer: CorsLayer::new(),
        }
    }
}

impl Plugin for CorsPlugin {
    fn name(&self) -> &'static str {
        "gasket:cors"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    fn layers(&self, _context: &LayerContext) -> Vec<TaggedLayer> {
        let layer = self.layer.clone();
        vec![TaggedLayer::new(
            MiddlewareSlot::TransportSecurity,
            move |router: Router| router.layer(layer),
        )]
    }
}

/// Response compression middleware plugin.
///
/// Uses `tower-http` compression and negotiates algorithms based on the
/// request's `Accept-Encoding` header.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionPlugin;

impl Plugin for CompressionPlugin {
    fn name(&self) -> &'static str {
        "gasket:compression"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    fn layers(&self, _context: &LayerContext) -> Vec<TaggedLayer> {
        vec![TaggedLayer::new(
            MiddlewareSlot::TransportSecurity,
            |router: Router| router.layer(CompressionLayer::new()),
        )]
    }
}

/// Standard secure response headers plugin.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecureHeadersPlugin;

impl Plugin for SecureHeadersPlugin {
    fn name(&self) -> &'static str {
        "gasket:secure-headers"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    fn layers(&self, _context: &LayerContext) -> Vec<TaggedLayer> {
        vec![TaggedLayer::new(
            MiddlewareSlot::TransportSecurity,
            |router: Router| router.layer(axum::middleware::from_fn(secure_headers_middleware)),
        )]
    }
}

/// Request timeout middleware plugin.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutPlugin {
    timeout: Duration,
}

impl TimeoutPlugin {
    /// Create a timeout plugin with the given maximum request duration.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Create a timeout plugin from seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self {
            timeout: Duration::from_secs(seconds),
        }
    }
}

impl Default for TimeoutPlugin {
    fn default() -> Self {
        Self::from_secs(30)
    }
}

impl Plugin for TimeoutPlugin {
    fn name(&self) -> &'static str {
        "gasket:timeout"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    fn layers(&self, _context: &LayerContext) -> Vec<TaggedLayer> {
        let timeout = self.timeout;
        vec![TaggedLayer::new(
            MiddlewareSlot::TransportSecurity,
            move |router: Router| {
                router.layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    timeout,
                ))
            },
        )]
    }
}

/// Add common browser-facing security headers when a handler has not set them.
async fn secure_headers_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    insert_if_missing(response.headers_mut(), "x-content-type-options", "nosniff");
    insert_if_missing(response.headers_mut(), "x-frame-options", "DENY");
    insert_if_missing(
        response.headers_mut(),
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
    response
}

fn insert_if_missing(headers: &mut http::HeaderMap, name: &'static str, value: &'static str) {
    let name = HeaderName::from_static(name);
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use http::StatusCode;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn secure_headers_are_added_without_handler_boilerplate() {
        let plugin = SecureHeadersPlugin;
        let layer = plugin
            .layers(&LayerContext::new(
                crate::config::AppConfigDefinition::new("test")
                    .resolve()
                    .expect("resolve config"),
                http::Extensions::new(),
            ))
            .into_iter()
            .next()
            .expect("secure headers layer");
        let app = layer.layer.apply(Router::new().route("/", get(ok)));

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            response.headers().get("x-frame-options"),
            Some(&HeaderValue::from_static("DENY"))
        );
    }
}
