//! Application engine: builder, lifecycle orchestration, and runtime container.
//!
//! [`GasketAppBuilder`] runs the full plugin lifecycle (validate → sort →
//! init → configure → prepare) and produces a [`GasketApp`] that holds
//! the sorted plugins, resolved config, actions, and shared extensions.

use std::collections::HashMap;

use crate::BoxError;
use crate::config::{AppConfig, AppConfigDefinition};
use crate::pipeline::MiddlewareSlot;

use crate::BoxFuture;

use super::{
    ActionArgs, ActionResult, BoxAction, InitContext, LayerContext, Plugin, PluginHandle,
    PrepareContext, ReadyContext, RouteContext, ShutdownContext, TaggedLayer, TaggedRoute,
    ordering::topological_sort,
};

/// Default maximum request body size applied to Public and Protected
/// routes. Set generously enough to accommodate JSON-heavy APIs but
/// small enough to prevent a single client from exhausting memory by
/// posting an arbitrarily large body.
///
/// Bare routes (e.g. liveness probes) are intentionally unbounded
/// because they do not read request bodies.
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// A fully configured application with plugins, config, and shared state.
///
/// Created via [`GasketAppBuilder::build()`]. Once built, the app's
/// plugins have been sorted, initialized, configured, and prepared.
/// Call [`ServerPlugin::run()`](crate::server::ServerPlugin::run) to start
/// serving HTTP traffic.
pub struct GasketApp {
    plugins: Vec<PluginHandle>,
    actions: HashMap<String, BoxAction>,
    /// The resolved application configuration, shared across all plugins.
    pub(crate) config: AppConfig,
    /// Shared extension map populated during the prepare phase.
    pub(crate) extensions: http::Extensions,
    /// Maximum request body size applied to Public and Protected
    /// routes. Operators override the [`DEFAULT_REQUEST_BODY_LIMIT`]
    /// default via [`GasketAppBuilder::request_body_limit`].
    pub(crate) request_body_limit: usize,
    /// Named authentication chains registered via
    /// [`GasketAppBuilder::auth_chain`]. Each entry backs the routes
    /// tagged [`RouteGroup::ProtectedWith`](super::RouteGroup::ProtectedWith)
    /// with the matching name. Wrapped in `Arc` because the axum auth
    /// middleware takes its state by shared reference.
    #[cfg(feature = "auth")]
    pub(crate) named_auth: HashMap<String, std::sync::Arc<crate::auth::AuthMiddlewareState>>,
}

impl std::fmt::Debug for GasketApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GasketApp")
            .field("config", &self.config)
            .field(
                "plugins",
                &self.plugins.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .field("actions", &self.actions.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl GasketApp {
    /// Create a new builder for configuring and assembling the application.
    pub fn builder() -> GasketAppBuilder {
        GasketAppBuilder {
            plugins: Vec::new(),
            config_def: None,
            request_body_limit: DEFAULT_REQUEST_BODY_LIMIT,
            #[cfg(feature = "auth")]
            named_auth: HashMap::new(),
        }
    }

    /// The resolved application configuration.
    #[must_use]
    pub const fn config(&self) -> &AppConfig {
        &self.config
    }

    /// The shared extension map populated during the prepare phase.
    #[must_use]
    pub const fn extensions(&self) -> &http::Extensions {
        &self.extensions
    }

    /// The registered plugins in topological order.
    #[must_use]
    pub fn plugins(&self) -> &[PluginHandle] {
        &self.plugins
    }

    /// Assemble the complete axum `Router` from plugin routes and layers.
    ///
    /// Routes are split into groups with different middleware stacks:
    /// - **Bare**: no middleware (liveness probes)
    /// - **Public**: transport security + logging + request body size limit
    /// - **Protected**: transport security + full protected middleware stack
    ///   (the global auth layer, rate limiting, body limit, ...)
    /// - **`ProtectedWith(name)`**: the same protected stack as
    ///   **Protected**, except the global authentication layer is replaced
    ///   by the *named* chain registered via
    ///   [`GasketAppBuilder::auth_chain`]. Every other protected-slot layer
    ///   (rate limiting, transactions, custom layers), logging, the request
    ///   body limit, and the outer transport-security layers still apply.
    ///   This lets specific endpoints sit behind different credentials (for
    ///   example a static shared Bearer token) without leaving the
    ///   protected pipeline.
    ///
    /// Public, Protected, and `ProtectedWith` routes get a body limit of
    /// [`DEFAULT_REQUEST_BODY_LIMIT`] applied via `tower_http`. Without it
    /// any unbounded extractor or streaming body handler would let a
    /// caller post arbitrarily large payloads.
    ///
    /// This is the same router that `ServerPlugin::run()` uses internally.
    /// Useful for building test routers that match production behavior.
    ///
    /// # Panics
    ///
    /// Panics if a route is tagged
    /// [`RouteGroup::ProtectedWith(name)`](super::RouteGroup::ProtectedWith)
    /// but no authentication chain was registered for `name` via
    /// [`GasketAppBuilder::auth_chain`]. Failing loudly at startup is
    /// deliberate: silently serving such a route would expose it
    /// unauthenticated.
    pub fn build_router(&self) -> axum::Router {
        let tagged_routes = self.collect_routes();

        let mut bare_router = axum::Router::new();
        let mut public_router = axum::Router::new();
        let mut protected_router = axum::Router::new();
        // Routes tagged `ProtectedWith(name)`, bucketed by name. Each
        // bucket becomes its own router with the named auth chain swapped
        // in for the global one.
        let mut named_routers: HashMap<&'static str, axum::Router> = HashMap::new();

        for tagged in tagged_routes {
            match tagged.group {
                super::RouteGroup::Bare => bare_router = bare_router.merge(tagged.router),
                super::RouteGroup::Public => public_router = public_router.merge(tagged.router),
                super::RouteGroup::Protected => {
                    protected_router = protected_router.merge(tagged.router);
                }
                super::RouteGroup::ProtectedWith(name) => {
                    let entry = named_routers.entry(name).or_default();
                    *entry = std::mem::take(entry).merge(tagged.router);
                }
            }
        }

        let logged_public = public_router
            .layer(axum::middleware::from_fn(
                crate::observability::logging_middleware,
            ))
            .layer(tower_http::limit::RequestBodyLimitLayer::new(
                self.request_body_limit,
            ));

        // Default protected router: fold every non-transport layer (the
        // global authentication layer included) in reverse-slot order, then
        // add logging and the body limit. This code path is unchanged from
        // before named chains existed.
        let (transport_layers, protected_layers) = self.partition_transport_layers();
        let mut protected_router = protected_router;
        for tagged_layer in protected_layers.into_iter().rev() {
            protected_router = tagged_layer.layer.apply(protected_router);
        }
        let protected_router = protected_router
            .layer(axum::middleware::from_fn(
                crate::observability::logging_middleware,
            ))
            .layer(tower_http::limit::RequestBodyLimitLayer::new(
                self.request_body_limit,
            ));

        let mut instrumented_router = axum::Router::new()
            .merge(logged_public)
            .merge(protected_router);

        // Named protected routers: each gets the protected stack with its
        // own auth chain in place of the global authentication layer.
        instrumented_router =
            self.apply_named_protected_routers(instrumented_router, named_routers);

        // Transport-security layers (CORS/HSTS/compression) wrap the public,
        // protected, and named routers together.
        for tagged_layer in transport_layers.into_iter().rev() {
            instrumented_router = tagged_layer.layer.apply(instrumented_router);
        }

        axum::Router::new()
            .merge(bare_router)
            .merge(instrumented_router)
    }

    /// Split freshly collected layers into the transport-security layers
    /// (applied outermost) and the remaining protected-stack layers.
    ///
    /// Each call to [`Self::collect_layers`] rebuilds the layer closures,
    /// so callers that need a second independent set of layers (the named
    /// protected routers) must call this again rather than reuse a consumed
    /// `Vec` — [`crate::plugin::RouterTransform`] is `FnOnce`.
    fn partition_transport_layers(&self) -> (Vec<TaggedLayer>, Vec<TaggedLayer>) {
        let mut transport_layers = Vec::new();
        let mut protected_layers = Vec::new();
        for tagged_layer in self.collect_layers() {
            if tagged_layer.slot == MiddlewareSlot::TransportSecurity {
                transport_layers.push(tagged_layer);
            } else {
                protected_layers.push(tagged_layer);
            }
        }
        (transport_layers, protected_layers)
    }

    /// Apply each named protected router's middleware stack and merge it
    /// into `router`.
    ///
    /// For every `name → sub-router`, this rebuilds the protected stack
    /// (logging, body limit, and every non-transport layer *except* the
    /// global [`MiddlewareSlot::Authentication`] layer) and installs the
    /// named chain's auth middleware in the authentication slot's place.
    ///
    /// # Panics
    ///
    /// Panics if a named router has no registered chain — see
    /// [`Self::build_router`].
    // A missing named chain is an unrecoverable build-time misconfiguration:
    // serving the route unauthenticated would be a security hole, so we fail
    // loudly rather than return a fallible `Result` that a caller could
    // ignore at startup.
    #[allow(clippy::panic)]
    #[cfg(feature = "auth")]
    fn apply_named_protected_routers(
        &self,
        mut router: axum::Router,
        named_routers: HashMap<&'static str, axum::Router>,
    ) -> axum::Router {
        for (name, sub_router) in named_routers {
            let Some(named_state) = self.named_auth.get(name) else {
                panic!("no auth chain registered for ProtectedWith(\"{name}\")");
            };

            // Re-collect layers so the FnOnce closures are fresh for this
            // router, and drop the global authentication layer — the named
            // chain replaces it.
            let (_transport, protected_layers) = self.partition_transport_layers();
            let mut sub_router = sub_router;
            for tagged_layer in protected_layers
                .into_iter()
                .filter(|layer| layer.slot != MiddlewareSlot::Authentication)
                .rev()
            {
                sub_router = tagged_layer.layer.apply(sub_router);
            }

            // Named authentication layer in place of the global one.
            sub_router = sub_router.layer(axum::middleware::from_fn_with_state(
                std::sync::Arc::clone(named_state),
                crate::auth::auth_middleware,
            ));

            // Mirror the default protected router: logging + body limit.
            let sub_router = sub_router
                .layer(axum::middleware::from_fn(
                    crate::observability::logging_middleware,
                ))
                .layer(tower_http::limit::RequestBodyLimitLayer::new(
                    self.request_body_limit,
                ));

            router = router.merge(sub_router);
        }
        router
    }

    /// Without the `auth` feature there is no way to register a named
    /// chain, so any `ProtectedWith` route is a configuration error.
    ///
    /// # Panics
    ///
    /// Panics if any `ProtectedWith` route exists, since no chain can be
    /// registered without the `auth` feature.
    // Same rationale as the `auth`-enabled variant: an unauthenticatable
    // protected route is a hard build-time error, not a recoverable one.
    #[allow(clippy::panic)]
    #[cfg(not(feature = "auth"))]
    fn apply_named_protected_routers(
        &self,
        router: axum::Router,
        named_routers: HashMap<&'static str, axum::Router>,
    ) -> axum::Router {
        if let Some(name) = named_routers.keys().next() {
            panic!(
                "no auth chain registered for ProtectedWith(\"{name}\"): \
                 named chains require the `auth` feature"
            );
        }
        router
    }

    /// Invoke a named action registered during the init phase.
    ///
    /// # Errors
    /// Returns an error if no action is registered under `name`.
    pub fn invoke_action(
        &self,
        name: &str,
        args: ActionArgs,
    ) -> Result<BoxFuture<'static, ActionResult>, BoxError> {
        let action = self
            .actions
            .get(name)
            .ok_or_else(|| format!("Action '{name}' not found"))?;
        Ok(action(args))
    }

    /// Invoke a named action and downcast its result to the expected type.
    ///
    /// # Errors
    /// Returns an error if no action is registered under `name`, if the action
    /// fails, or if the action returned a different type than `T`.
    pub async fn invoke<T>(&self, name: &str, args: ActionArgs) -> Result<T, BoxError>
    where
        T: std::any::Any + Send + 'static,
    {
        let result = self.invoke_action(name, args)?.await?;
        result.downcast::<T>().map(|boxed| *boxed).map_err(|_| {
            format!(
                "Action '{name}' returned a different type than {}",
                std::any::type_name::<T>()
            )
            .into()
        })
    }

    /// Collect and sort all middleware layers from plugins by slot order.
    #[must_use]
    pub fn collect_layers(&self) -> Vec<TaggedLayer> {
        let ctx = LayerContext::new(self.config.clone(), self.extensions.clone());
        let mut layers: Vec<TaggedLayer> = Vec::new();
        for plugin in &self.plugins {
            layers.extend(plugin.layers(&ctx));
        }
        layers.sort_by_key(|l| l.slot);
        layers
    }

    /// Collect all routes from plugins.
    #[must_use]
    pub fn collect_routes(&self) -> Vec<TaggedRoute> {
        let ctx = RouteContext::new(self.config.clone(), self.extensions.clone());
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            routes.extend(plugin.routes(&ctx));
        }
        routes
    }

    /// Notify all plugins that the server is ready and accepting traffic.
    ///
    /// # Errors
    /// Returns the first error reported by a plugin's `ready` hook. Subsequent
    /// plugins are not called once a plugin fails.
    pub async fn ready(&self, local_addr: std::net::SocketAddr) -> Result<(), BoxError> {
        let ctx = ReadyContext::new(self.config.clone(), self.extensions.clone(), local_addr);
        for plugin in &self.plugins {
            plugin.ready(&ctx).await?;
        }
        Ok(())
    }

    /// Shut down all plugins in reverse topological order.
    ///
    /// Per-plugin shutdown errors are logged but do not abort the
    /// sequence — losing one plugin's cleanup should not prevent later
    /// plugins from getting their chance to release resources. The
    /// return type is therefore `()` rather than `Result`; an operator
    /// reading logs is the authoritative source of "did anything fail."
    pub async fn shutdown(&self) {
        let ctx = ShutdownContext::new(self.extensions.clone());
        for plugin in self.plugins.iter().rev() {
            if let Err(e) = plugin.shutdown(&ctx).await {
                tracing::error!(plugin = plugin.name(), error = %e, "Plugin shutdown failed");
            }
        }
    }
}

/// Builder for [`GasketApp`].
///
/// Runs the full plugin lifecycle during [`build()`](Self::build):
/// validate dependencies → topological sort → init → configure → prepare.
/// If `prepare` fails for any plugin, already-prepared plugins are
/// shut down in reverse order before the error propagates.
#[must_use = "GasketAppBuilder must be consumed by .build() to produce a GasketApp"]
pub struct GasketAppBuilder {
    plugins: Vec<PluginHandle>,
    config_def: Option<AppConfigDefinition>,
    request_body_limit: usize,
    /// Named authentication chains, keyed by the name used in
    /// [`RouteGroup::ProtectedWith`](super::RouteGroup::ProtectedWith).
    /// Populated by [`Self::auth_chain`].
    #[cfg(feature = "auth")]
    named_auth: HashMap<String, std::sync::Arc<crate::auth::AuthMiddlewareState>>,
}

impl std::fmt::Debug for GasketAppBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GasketAppBuilder")
            .field(
                "plugins",
                &self.plugins.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl GasketAppBuilder {
    /// Add a plugin by value (auto-boxed).
    pub fn plugin(mut self, plugin: impl Plugin) -> Self {
        self.plugins.push(PluginHandle::new(plugin));
        self
    }

    /// Add an already-created plugin handle (useful for dynamic registration).
    pub fn plugin_handle(mut self, plugin: PluginHandle) -> Self {
        self.plugins.push(plugin);
        self
    }

    /// Add an already-created plugin handle (useful for dynamic registration).
    ///
    /// Prefer [`Self::plugin_handle`] in new code.
    pub fn plugin_boxed(self, plugin: PluginHandle) -> Self {
        self.plugin_handle(plugin)
    }

    /// Add a preset of plugin handles, typically from `presets::api()`.
    pub fn preset(mut self, plugins: Vec<PluginHandle>) -> Self {
        self.plugins.extend(plugins);
        self
    }

    /// Set the application config definition (loaded from TOML/YAML or built in code).
    pub fn config(mut self, config_def: AppConfigDefinition) -> Self {
        self.config_def = Some(config_def);
        self
    }

    /// Override the maximum request body size applied to Public and
    /// Protected routes (default: [`DEFAULT_REQUEST_BODY_LIMIT`]).
    ///
    /// Set this above the default for file-upload APIs, or below to
    /// further tighten the cap on JSON-only services.
    pub const fn request_body_limit(mut self, bytes: usize) -> Self {
        self.request_body_limit = bytes;
        self
    }

    /// Register a named authentication chain.
    ///
    /// Routes tagged
    /// [`RouteGroup::ProtectedWith(name)`](super::RouteGroup::ProtectedWith)
    /// are authenticated by the chain registered under that `name` instead
    /// of the global authentication layer that backs plain
    /// [`RouteGroup::Protected`](super::RouteGroup::Protected) routes. Aside
    /// from the swapped authentication layer they receive the identical
    /// protected middleware stack (logging, request body limit, rate
    /// limiting, transactions, and any custom-slot layers).
    ///
    /// Register as many distinct chains as the application needs; each
    /// `name` maps to one chain. Registering the same `name` twice keeps
    /// the last chain.
    ///
    /// If a `ProtectedWith` route references a `name` that was never
    /// registered, [`build_router`](GasketApp::build_router) panics at
    /// startup rather than silently serving the route unauthenticated.
    ///
    /// Requires the `auth` feature.
    ///
    /// ```no_run
    /// # use rusty_gasket::plugin::GasketApp;
    /// # use rusty_gasket::auth::{AuthChain, AuthMiddlewareState, StaticBearerBackend};
    /// let builder = GasketApp::builder().auth_chain(
    ///     "push",
    ///     AuthMiddlewareState::new(
    ///         AuthChain::new().backend(StaticBearerBackend::new("shared-secret")),
    ///     ),
    /// );
    /// # let _ = builder;
    /// ```
    #[cfg(feature = "auth")]
    pub fn auth_chain(
        mut self,
        name: impl Into<String>,
        state: crate::auth::AuthMiddlewareState,
    ) -> Self {
        self.named_auth
            .insert(name.into(), std::sync::Arc::new(state));
        self
    }

    /// Build the app through the full plugin lifecycle.
    ///
    /// Runs validation, dependency ordering, and the `init`, `configure`, and
    /// `prepare` plugin phases in sequence. If `prepare` fails for any plugin,
    /// the already-prepared plugins are shut down before the error returns.
    ///
    /// # Errors
    /// Returns an error if duplicate plugin names are registered, dependency
    /// validation fails, or any plugin's `init`, `configure`, or `prepare`
    /// hook fails.
    pub async fn build(mut self) -> Result<GasketApp, BoxError> {
        // Phase 0: check for duplicate plugin names
        let plugin_names: Vec<&str> = self.plugins.iter().map(|p| p.name()).collect();
        {
            let mut seen = std::collections::HashSet::new();
            for name in &plugin_names {
                if !seen.insert(*name) {
                    return Err(format!("Duplicate plugin name: '{name}'").into());
                }
            }
        }

        // Phase 0: validate that all declared dependencies are present
        for plugin in &self.plugins {
            for dep in plugin.dependencies() {
                if !plugin_names.contains(&dep) {
                    return Err(format!(
                        "Plugin '{}' requires missing dependency '{dep}'",
                        plugin.name()
                    )
                    .into());
                }
            }
        }

        // Phase 0.5: topological sort from ordering constraints
        let sorted_indices = topological_sort(&self.plugins)?;
        let mut sorted_plugins: Vec<PluginHandle> = Vec::with_capacity(self.plugins.len());
        let mut old_plugins: Vec<Option<PluginHandle>> =
            self.plugins.into_iter().map(Some).collect();
        for idx in sorted_indices {
            if let Some(p) = old_plugins[idx].take() {
                sorted_plugins.push(p);
            }
        }
        self.plugins = sorted_plugins;

        // Phase 1: init (synchronous — register actions and hooks)
        let mut init_ctx = InitContext::new();
        for plugin in &self.plugins {
            plugin.init(&mut init_ctx);
        }

        // Phase 2: configure (waterfall — each plugin transforms the config)
        let config_def = self.config_def.unwrap_or_default();
        let mut config = config_def.resolve()?;
        for plugin in &self.plugins {
            config = plugin.configure(config);
        }

        // Phase 3: prepare (async with rollback on failure)
        let mut prepare_ctx = PrepareContext::new(config.clone(), http::Extensions::new());
        for (prepared_count, plugin) in self.plugins.iter().enumerate() {
            if let Err(e) = plugin.prepare(&mut prepare_ctx).await {
                tracing::error!(
                    plugin = plugin.name(),
                    error = %e,
                    "Plugin prepare failed, rolling back"
                );
                // Roll back already-prepared plugins in reverse order,
                // passing the real extensions so plugins can clean up their state
                let shutdown_ctx = ShutdownContext::new(prepare_ctx.extensions.clone());
                for prev_plugin in self.plugins[..prepared_count].iter().rev() {
                    if let Err(shutdown_err) = prev_plugin.shutdown(&shutdown_ctx).await {
                        tracing::warn!(
                            plugin = prev_plugin.name(),
                            error = %shutdown_err,
                            "Plugin shutdown failed during rollback"
                        );
                    }
                }
                return Err(e);
            }
        }

        let app = GasketApp {
            plugins: self.plugins,
            actions: init_ctx.into_actions(),
            config,
            extensions: prepare_ctx.extensions,
            request_body_limit: self.request_body_limit,
            #[cfg(feature = "auth")]
            named_auth: self.named_auth,
        };

        let plugin_names: Vec<&str> = app.plugins.iter().map(|p| p.name()).collect();
        tracing::info!(?plugin_names, "GasketApp built successfully");

        Ok(app)
    }
}
