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

    use axum::routing::get;
    use axum::{Json, Router};

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
            let spec_for_json = Arc::clone(&self.spec);
            let spec_route = Router::new().route(
                "/openapi.json",
                get(move || {
                    let s = Arc::clone(&spec_for_json);
                    async move { Json(s) }
                }),
            );

            // Swagger UI consumes the spec by value; clone the inner OpenApi
            // out of the Arc once at startup. The per-request `/openapi.json`
            // path is the hot loop; this construction runs only at boot.
            let swagger_route = {
                let swagger_ui = utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                    .url("/openapi.json", (*self.spec).clone());
                Router::new().merge(swagger_ui)
            };

            vec![
                TaggedRoute::new(RouteGroup::Public, spec_route),
                TaggedRoute::new(RouteGroup::Public, swagger_route),
            ]
        }
    }
}

#[cfg(feature = "openapi")]
pub use inner::OpenApiPlugin;
