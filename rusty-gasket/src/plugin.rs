//! Plugin system for Rusty Gasket.
//!
//! Plugins are the primary extension mechanism. Each plugin implements
//! the [`Plugin`] trait and participates in the application lifecycle:
//! `init → configure → prepare → ready → shutdown`. Plugins also
//! contribute middleware layers and routes via [`TaggedLayer`] and
//! [`TaggedRoute`].

mod engine;
mod ordering;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use axum::Router;

use crate::BoxError;
use crate::BoxFuture;
use crate::config::AppConfig;
use crate::pipeline::MiddlewareSlot;

pub use engine::{DEFAULT_REQUEST_BODY_LIMIT, GasketApp, GasketAppBuilder};
pub use ordering::{PluginOrdering, topological_sort};

/// The result type returned by named actions.
pub type ActionResult = Result<Box<dyn std::any::Any + Send>, BoxError>;

/// A type-erased async closure registered as a named action during init.
pub type BoxAction = Arc<dyn Fn(ActionArgs) -> BoxFuture<'static, ActionResult> + Send + Sync>;

/// Arguments passed to a [`BoxAction`] invocation.
pub type ActionArgs = Vec<Box<dyn std::any::Any + Send>>;

/// A type-erased router transformation for the middleware pipeline.
///
/// Plugins wrap their middleware (e.g., `from_fn_with_state`) in a closure
/// that applies it to a `Router`. This avoids Tower service type mismatches
/// between `BoxService` and axum's internal `Route` type.
pub type BoxRouterLayer = Box<dyn FnOnce(Router) -> Router + Send>;

/// A named router transformation used by the middleware pipeline.
///
/// This is the readable wrapper around the framework's boxed router closure.
/// Most plugin code creates one through [`TaggedLayer::new`] rather than
/// constructing this type directly.
pub struct RouterTransform {
    /// The one-shot closure that applies an axum/Tower middleware layer.
    ///
    /// It is boxed because each middleware closure has a unique compiler
    /// generated type, but the pipeline needs to store many of them together.
    layer: BoxRouterLayer,
}

impl RouterTransform {
    /// Create a router transform from a closure.
    #[must_use]
    pub fn new(layer: impl FnOnce(Router) -> Router + Send + 'static) -> Self {
        Self {
            layer: Box::new(layer),
        }
    }

    /// Apply the transform to a router and return the transformed router.
    pub fn apply(self, router: Router) -> Router {
        (self.layer)(router)
    }
}

impl std::fmt::Debug for RouterTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterTransform").finish_non_exhaustive()
    }
}

/// Controls which middleware stacks apply to a set of routes.
///
/// - `Bare` — no middleware at all (liveness probes). No logging, no
///   request body limit, no auth. Use only for handlers that read no
///   request body and intentionally bypass observability.
/// - `Public` — logging + request body size limit
///   ([`DEFAULT_REQUEST_BODY_LIMIT`]). Suitable for health checks,
///   docs, and Swagger UI.
/// - `Protected` — full middleware stack: logging, request body limit,
///   plus the per-plugin layers (auth, rate limiting, transactions, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteGroup {
    Bare,
    Public,
    Protected,
}

/// A middleware layer tagged with the pipeline slot it belongs to.
/// The server assembles layers in slot order regardless of plugin registration order.
#[non_exhaustive]
pub struct TaggedLayer {
    /// Where this middleware belongs in the protected request pipeline.
    pub slot: MiddlewareSlot,
    /// The router transformation to apply at that pipeline slot.
    pub layer: RouterTransform,
}

impl TaggedLayer {
    /// Create a tagged layer from a middleware closure.
    ///
    /// Avoids manual `Box::new(...)` wrapping — just pass a closure:
    /// ```ignore
    /// TaggedLayer::new(MiddlewareSlot::Authentication, |router| {
    ///     router.layer(my_middleware)
    /// })
    /// ```
    pub fn new(
        slot: MiddlewareSlot,
        layer: impl FnOnce(Router) -> Router + Send + 'static,
    ) -> Self {
        Self {
            slot,
            layer: RouterTransform::new(layer),
        }
    }
}

impl std::fmt::Debug for TaggedLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedLayer")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

/// A router tagged with the route group it belongs to.
/// The server merges routes into separate groups with different middleware stacks.
#[non_exhaustive]
pub struct TaggedRoute {
    /// The middleware group this router should be merged into.
    pub group: RouteGroup,
    /// The axum router contributed by a plugin.
    pub router: Router,
}

impl TaggedRoute {
    /// Create a tagged route from a group and router.
    #[must_use]
    pub const fn new(group: RouteGroup, router: Router) -> Self {
        Self { group, router }
    }
}

impl std::fmt::Debug for TaggedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedRoute")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

/// Context available during the `init` lifecycle phase.
///
/// Plugins use this to register named actions — async closures that can
/// be invoked by name at runtime via [`GasketApp::invoke_action`].
/// Duplicate action names are a hard error (prevents silent collisions).
pub struct InitContext {
    actions: HashMap<String, BoxAction>,
}

impl InitContext {
    #[must_use]
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Register a named action. Returns an error if the name is already taken.
    ///
    /// # Errors
    /// Returns an error if another plugin has already registered an action
    /// with the same `name`.
    pub fn register_action(&mut self, name: &str, action: BoxAction) -> Result<(), BoxError> {
        if self.actions.contains_key(name) {
            return Err(format!("Action '{name}' already registered by another plugin").into());
        }
        self.actions.insert(name.to_string(), action);
        Ok(())
    }

    /// Register a named async action without writing boxed-future boilerplate.
    ///
    /// The action receives type-erased arguments and returns a concrete value.
    /// Rusty Gasket boxes the returned value internally so callers can retrieve
    /// it with [`GasketApp::invoke`].
    ///
    /// # Errors
    /// Returns an error if another plugin has already registered an action
    /// with the same `name`.
    pub fn register_action_fn<Function, FutureOutput, Output>(
        &mut self,
        name: &str,
        action: Function,
    ) -> Result<(), BoxError>
    where
        Function: Fn(ActionArgs) -> FutureOutput + Send + Sync + 'static,
        FutureOutput: Future<Output = Result<Output, BoxError>> + Send + 'static,
        Output: std::any::Any + Send + 'static,
    {
        let action = Arc::new(action);
        self.register_action(
            name,
            Arc::new(move |args| {
                let action = Arc::clone(&action);
                Box::pin(async move {
                    let result = action(args).await?;
                    let result: Box<dyn std::any::Any + Send> = Box::new(result);
                    Ok(result)
                })
            }),
        )
    }

    pub(crate) fn into_actions(self) -> HashMap<String, BoxAction> {
        self.actions
    }
}

impl Default for InitContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InitContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitContext")
            .field("actions", &self.actions.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Context available during the `prepare` lifecycle phase.
/// Plugins do async setup here (connect to databases, warm caches).
/// The `extensions` map is shared across all plugins for passing state.
#[derive(Debug)]
#[non_exhaustive]
pub struct PrepareContext {
    pub config: AppConfig,
    pub extensions: http::Extensions,
}

impl PrepareContext {
    /// Create a `PrepareContext`. Used by the framework engine and tests.
    #[must_use]
    pub const fn new(config: AppConfig, extensions: http::Extensions) -> Self {
        Self { config, extensions }
    }
}

/// Context available when plugins contribute middleware layers.
#[derive(Debug)]
#[non_exhaustive]
pub struct LayerContext {
    pub config: AppConfig,
    pub extensions: http::Extensions,
}

impl LayerContext {
    /// Create a `LayerContext`. Used by the framework engine and tests.
    #[must_use]
    pub const fn new(config: AppConfig, extensions: http::Extensions) -> Self {
        Self { config, extensions }
    }
}

/// Context available when plugins contribute routes.
#[derive(Debug)]
#[non_exhaustive]
pub struct RouteContext {
    pub config: AppConfig,
    pub extensions: http::Extensions,
}

impl RouteContext {
    /// Create a `RouteContext`. Used by the framework engine and tests.
    #[must_use]
    pub const fn new(config: AppConfig, extensions: http::Extensions) -> Self {
        Self { config, extensions }
    }
}

/// Context available during the `ready` lifecycle phase.
/// At this point the server is bound and about to accept traffic.
#[non_exhaustive]
pub struct ReadyContext {
    pub config: AppConfig,
    pub extensions: http::Extensions,
    pub local_addr: std::net::SocketAddr,
}

impl ReadyContext {
    /// Create a `ReadyContext`. Used by the framework engine and tests.
    #[must_use]
    pub const fn new(
        config: AppConfig,
        extensions: http::Extensions,
        local_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            config,
            extensions,
            local_addr,
        }
    }
}

impl std::fmt::Debug for ReadyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyContext")
            .field("config", &self.config)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// Context available during the `shutdown` lifecycle phase.
/// Plugins run in reverse topological order during shutdown.
#[non_exhaustive]
pub struct ShutdownContext {
    pub extensions: http::Extensions,
}

impl ShutdownContext {
    /// Create a `ShutdownContext`. Used by the framework engine and tests.
    #[must_use]
    pub const fn new(extensions: http::Extensions) -> Self {
        Self { extensions }
    }
}

impl std::fmt::Debug for ShutdownContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownContext").finish_non_exhaustive()
    }
}

/// The core extension trait for Rusty Gasket.
///
/// Plugins participate in a lifecycle that runs during application startup
/// and shutdown. Each method has a default no-op implementation so plugins
/// only need to override the phases they care about.
///
/// # Lifecycle order
///
/// 1. `init` — synchronous, infallible, register named actions
/// 2. `configure` — synchronous, infallible waterfall, transform config
/// 3. `prepare` — async, fallible, connect to external resources
/// 4. `layers` + `routes` — synchronous, infallible accessors invoked when
///    the router is assembled (between `prepare` and `ready`)
/// 5. `ready` — async, fallible, server is bound and accepting traffic
/// 6. `shutdown` — async, fallible best-effort cleanup; runs in reverse
///    topological order; errors are logged but do not abort the
///    sequence (the framework calls every plugin's `shutdown` even if
///    one fails)
///
/// If `prepare` fails for any plugin, already-prepared plugins receive
/// `shutdown` in reverse order before the error propagates. `ready` and
/// `shutdown` errors are logged but do not abort the sequence.
///
/// # Plugin naming convention
///
/// Built-in framework plugins use the `gasket:*` namespace (for
/// example `gasket:health`, `gasket:server`). When listing
/// [`Self::dependencies`], use the exact `name()` strings returned by
/// the plugins you depend on; the framework matches by literal string
/// and a typo produces a `"requires missing dependency"` build error.
///
/// # Threading
///
/// All lifecycle methods run on the same async runtime as the rest of
/// the application. The synchronous methods (`init`, `configure`,
/// `layers`, `routes`) must not block — perform any I/O in
/// `prepare`/`ready`/`shutdown` instead.
pub trait Plugin: Send + Sync + 'static {
    /// Human-readable name for diagnostics and logging. Used as the
    /// match key for `dependencies()` so the literal string matters;
    /// built-ins use the `gasket:*` namespace.
    ///
    /// Returns `&'static str` because plugin names are compile-time
    /// constants in every known implementation; if a dynamic name is
    /// ever needed, leak via `Box::leak`.
    fn name(&self) -> &'static str;

    /// Ordering constraints relative to other plugins.
    /// The framework topologically sorts plugins based on these constraints.
    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::default()
    }

    /// Hard dependencies on other plugins. Build fails if any are
    /// missing. Identify dependencies by the exact `name()` they
    /// return (e.g. `"gasket:health"`).
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Synchronous, infallible init phase. Register named actions via
    /// `ctx.register_action()`. Validation that can fail belongs in
    /// `prepare` so the error can propagate.
    fn init(&self, _ctx: &mut InitContext) {}

    /// Config waterfall. Each plugin can transform the resolved config.
    fn configure(&self, config: AppConfig) -> AppConfig {
        config
    }

    /// Async prepare phase. Connect to databases, warm caches, etc.
    fn prepare<'ctx>(
        &'ctx self,
        _ctx: &'ctx mut PrepareContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send + 'ctx {
        async { Ok(()) }
    }

    /// Called when the server is fully ready and accepting traffic.
    fn ready<'ctx>(
        &'ctx self,
        _ctx: &'ctx ReadyContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send + 'ctx {
        async { Ok(()) }
    }

    /// Called during graceful shutdown (reverse plugin order).
    fn shutdown<'ctx>(
        &'ctx self,
        _ctx: &'ctx ShutdownContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send + 'ctx {
        async { Ok(()) }
    }

    /// Return middleware layers tagged with pipeline slots.
    fn layers(&self, _ctx: &LayerContext) -> Vec<TaggedLayer> {
        Vec::new()
    }

    /// Return routes tagged with route groups.
    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        Vec::new()
    }
}

/// Dyn-compatible version of [`Plugin`] used only by the framework runtime.
///
/// Public plugin implementations use the readable [`Plugin`] trait with
/// plain `async fn` hooks. The runtime still needs one list containing many
/// different plugin types, so this private trait performs the required type
/// erasure in one named place.
trait ErasedPlugin: Send + Sync + 'static {
    /// Return the public plugin name.
    fn name(&self) -> &'static str;

    /// Return ordering constraints used by the dependency sorter.
    fn ordering(&self) -> PluginOrdering;

    /// Return hard plugin dependencies by name.
    fn dependencies(&self) -> Vec<&str>;

    /// Forward the synchronous init hook.
    fn init(&self, ctx: &mut InitContext);

    /// Forward the config transformation hook.
    fn configure(&self, config: AppConfig) -> AppConfig;

    /// Forward the async prepare hook as a boxed future.
    fn prepare<'ctx>(
        &'ctx self,
        ctx: &'ctx mut PrepareContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>>;

    /// Forward the async ready hook as a boxed future.
    fn ready<'ctx>(&'ctx self, ctx: &'ctx ReadyContext) -> BoxFuture<'ctx, Result<(), BoxError>>;

    /// Forward the async shutdown hook as a boxed future.
    fn shutdown<'ctx>(
        &'ctx self,
        ctx: &'ctx ShutdownContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>>;

    /// Forward middleware contributions.
    fn layers(&self, ctx: &LayerContext) -> Vec<TaggedLayer>;

    /// Forward route contributions.
    fn routes(&self, ctx: &RouteContext) -> Vec<TaggedRoute>;
}

impl<T> ErasedPlugin for T
where
    T: Plugin,
{
    fn name(&self) -> &'static str {
        Plugin::name(self)
    }

    fn ordering(&self) -> PluginOrdering {
        Plugin::ordering(self)
    }

    fn dependencies(&self) -> Vec<&str> {
        Plugin::dependencies(self)
    }

    fn init(&self, ctx: &mut InitContext) {
        Plugin::init(self, ctx);
    }

    fn configure(&self, config: AppConfig) -> AppConfig {
        Plugin::configure(self, config)
    }

    fn prepare<'ctx>(
        &'ctx self,
        ctx: &'ctx mut PrepareContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>> {
        // The public trait returns an anonymous future. Boxing happens here so
        // callers and plugin authors never have to name that future type.
        Box::pin(Plugin::prepare(self, ctx))
    }

    fn ready<'ctx>(&'ctx self, ctx: &'ctx ReadyContext) -> BoxFuture<'ctx, Result<(), BoxError>> {
        // Keep async lifecycle storage dynamic without requiring async-trait
        // or boxed-future syntax in plugin implementations.
        Box::pin(Plugin::ready(self, ctx))
    }

    fn shutdown<'ctx>(
        &'ctx self,
        ctx: &'ctx ShutdownContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>> {
        // Shutdown uses the same erased future shape so rollback and normal
        // graceful shutdown can share one plugin list.
        Box::pin(Plugin::shutdown(self, ctx))
    }

    fn layers(&self, ctx: &LayerContext) -> Vec<TaggedLayer> {
        Plugin::layers(self, ctx)
    }

    fn routes(&self, ctx: &RouteContext) -> Vec<TaggedRoute> {
        Plugin::routes(self, ctx)
    }
}

/// A plugin handle ready for dynamic registration or presets.
///
/// Most applications can pass plugin values directly to
/// [`GasketAppBuilder::plugin`]. Use `PluginHandle` when building a plugin
/// list dynamically, such as framework presets.
pub struct PluginHandle {
    /// The dyn-compatible plugin object used by the runtime lifecycle engine.
    inner: Box<dyn ErasedPlugin>,
}

impl PluginHandle {
    /// Store a plugin behind a readable framework handle.
    pub fn new(plugin: impl Plugin) -> Self {
        Self {
            inner: Box::new(plugin),
        }
    }

    /// Human-readable plugin name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// Plugin ordering constraints consumed by the sorter.
    pub(crate) fn ordering(&self) -> PluginOrdering {
        self.inner.ordering()
    }

    /// Hard plugin dependencies consumed by the dependency validator.
    pub(crate) fn dependencies(&self) -> Vec<&str> {
        self.inner.dependencies()
    }

    /// Run the plugin's init hook.
    pub(crate) fn init(&self, ctx: &mut InitContext) {
        self.inner.init(ctx);
    }

    /// Run the plugin's config transformation hook.
    pub(crate) fn configure(&self, config: AppConfig) -> AppConfig {
        self.inner.configure(config)
    }

    /// Run the plugin's async prepare hook.
    pub(crate) fn prepare<'ctx>(
        &'ctx self,
        ctx: &'ctx mut PrepareContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>> {
        self.inner.prepare(ctx)
    }

    /// Run the plugin's async ready hook.
    pub(crate) fn ready<'ctx>(
        &'ctx self,
        ctx: &'ctx ReadyContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>> {
        self.inner.ready(ctx)
    }

    /// Run the plugin's async shutdown hook.
    pub(crate) fn shutdown<'ctx>(
        &'ctx self,
        ctx: &'ctx ShutdownContext,
    ) -> BoxFuture<'ctx, Result<(), BoxError>> {
        self.inner.shutdown(ctx)
    }

    /// Collect middleware contributed by this plugin.
    pub(crate) fn layers(&self, ctx: &LayerContext) -> Vec<TaggedLayer> {
        self.inner.layers(ctx)
    }

    /// Collect routes contributed by this plugin.
    pub(crate) fn routes(&self, ctx: &RouteContext) -> Vec<TaggedRoute> {
        self.inner.routes(ctx)
    }
}

impl std::fmt::Debug for PluginHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PluginHandle").field(&self.name()).finish()
    }
}

/// Backward-compatible name for dynamic plugin storage.
///
/// Prefer [`PluginHandle`] in new framework and application code.
pub type BoxPlugin = PluginHandle;
