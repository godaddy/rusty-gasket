//! Friendly API recipes for common Rusty Gasket service tasks.
//!
//! This example is intentionally more complete than the quick start in the
//! root README. It shows the everyday patterns a new service usually needs:
//! public health checks, simple string processing, authenticated handlers,
//! JSON validation, path parameters, query parameters, and in-process tests.

pub mod routes;

use rusty_gasket::plugin::{Plugin, RouteContext, RouteGroup, TaggedRoute};

/// Plugin that contributes the recipe API routes to a Rusty Gasket app.
///
/// Application authors usually only need a small plugin like this: the
/// framework owns startup and middleware, while the plugin owns service routes.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecipePlugin;

impl Plugin for RecipePlugin {
    /// Stable plugin name used in diagnostics and dependency ordering.
    fn name(&self) -> &'static str {
        "example:recipe-api"
    }

    /// Register public and protected routes with the framework.
    fn routes(&self, _context: &RouteContext) -> Vec<TaggedRoute> {
        vec![
            TaggedRoute::new(RouteGroup::Public, routes::public_routes()),
            TaggedRoute::new(RouteGroup::Protected, routes::protected_routes()),
        ]
    }
}
