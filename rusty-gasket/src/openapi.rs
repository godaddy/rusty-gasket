//! OpenAPI integration via utoipa.
//!
//! The `openapi` feature is enabled by default. When available,
//! [`OpenApiPlugin`] provides:
//! - `GET /openapi.json` — the generated OpenAPI 3.1 spec
//! - `GET /swagger-ui/*` — interactive Swagger UI
//!
//! Routes are registered in the `Public` route group (logged but not
//! authenticated) so they are accessible without credentials.

#[cfg(feature = "openapi")]
mod inner {
    use std::sync::Arc;

    use axum::Router;

    use crate::plugin::{Plugin, PluginOrdering, RouteContext, RouteGroup, TaggedRoute};

    /// Lifecycle plugin that serves the OpenAPI spec and Swagger UI.
    ///
    /// The spec is provided at construction time — you build it using
    /// utoipa's `#[derive(OpenApi)]` on your API struct and pass it in.
    /// The spec is wrapped in an [`Arc`] so each request to `/openapi.json`
    /// only pays an atomic refcount bump rather than a deep clone of the
    /// (potentially large) document tree.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(utoipa::OpenApi)]
    /// #[openapi(paths(my_handler), components(schemas(MyType)))]
    /// struct ApiDoc;
    ///
    /// GasketApp::builder()
    ///     .plugin(OpenApiPlugin::new(ApiDoc::openapi()))
    ///     .build()
    ///     .await?;
    /// ```
    pub struct OpenApiPlugin {
        spec: Arc<utoipa::openapi::OpenApi>,
    }

    impl std::fmt::Debug for OpenApiPlugin {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OpenApiPlugin")
                .field("title", &self.spec.info.title)
                .field("version", &self.spec.info.version)
                .finish_non_exhaustive()
        }
    }

    impl OpenApiPlugin {
        /// Create the plugin with a pre-built OpenAPI spec.
        #[must_use]
        pub fn new(spec: utoipa::openapi::OpenApi) -> Self {
            Self {
                spec: Arc::new(spec),
            }
        }

        /// Create the plugin from a `utoipa` API document type.
        ///
        /// This is the novice-friendly path for generated services: handlers
        /// keep their `#[utoipa::path(...)]` documentation next to the code,
        /// the small API document type lists those handlers, and Rusty Gasket
        /// builds the plugin from the type without requiring callers to pass
        /// around the raw OpenAPI value.
        #[must_use]
        pub fn from_api_doc<ApiDoc>() -> Self
        where
            ApiDoc: utoipa::OpenApi,
        {
            Self::new(ApiDoc::openapi())
        }
    }

    impl Plugin for OpenApiPlugin {
        fn name(&self) -> &'static str {
            "gasket:openapi"
        }

        fn ordering(&self) -> PluginOrdering {
            PluginOrdering::default()
        }

        fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
            // `SwaggerUi::url(path, spec)` registers *two* things: the
            // interactive UI at `/swagger-ui`, and a `GET {path}` handler that
            // serves the spec JSON (as `Json(Arc<…>)`, so each request still
            // only pays an atomic refcount bump). It therefore already provides
            // `GET /openapi.json` — registering a second `/openapi.json` route
            // here would make axum's router merge panic at startup with
            // "Overlapping method route. Handler for `GET /openapi.json`
            // already exists". So the spec is registered exactly once, via the
            // Swagger UI builder. The inner `OpenApi` is cloned out of the Arc
            // once at startup (Swagger UI consumes it by value).
            let swagger_route = {
                let swagger_ui = utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                    .url("/openapi.json", (*self.spec).clone());
                Router::new().merge(swagger_ui)
            };

            vec![TaggedRoute::new(RouteGroup::Public, swagger_route)]
        }
    }
}

#[cfg(feature = "openapi")]
pub use inner::OpenApiPlugin;
