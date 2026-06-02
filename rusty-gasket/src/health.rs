//! Health check endpoints and build metadata.
//!
//! The [`HealthPlugin`] registers two routes:
//! - `GET /healthcheck` (Public group) — returns build metadata and component health
//! - `GET /livez` (Bare group) — returns 200 OK with no middleware

use std::future::Future;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::BoxFuture;
use crate::plugin::{Plugin, PluginOrdering, RouteContext, RouteGroup, TaggedRoute};

/// Health status reported by a [`HealthContributor`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Error,
}

/// Trait for components that contribute to the health check response.
/// Implement this for database pools, external service clients, etc.
///
/// # Concurrency and timeout
///
/// All registered contributors are polled concurrently by the
/// `/healthcheck` handler via `futures::join_all`, so implementers
/// must not assume serialization between calls.
///
/// Each `check()` is wrapped in a `tokio::time::timeout` of
/// [`HEALTH_CHECK_TIMEOUT`] (5 seconds). A `check()` that does not
/// resolve within that window is forcibly mapped to
/// `HealthStatus::Error` and the inner future is cancelled. Slow or
/// external probes (DB pings, RPCs to other services) should be run
/// out of band on a periodic task and cached locally — the `check()`
/// body should then just read the cache.
///
/// The cancellation contract is the standard `tokio` one: the inner
/// future is dropped at the next `.await`. Any work that cannot be
/// cancelled cleanly within 5 seconds is the implementer's problem
/// to surface (or move out of band).
pub trait HealthContributor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn check(&self) -> impl Future<Output = HealthStatus> + Send + '_;
}

trait ErasedHealthContributor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn check(&self) -> BoxFuture<'_, HealthStatus>;
}

impl<T> ErasedHealthContributor for T
where
    T: HealthContributor,
{
    fn name(&self) -> &'static str {
        HealthContributor::name(self)
    }

    fn check(&self) -> BoxFuture<'_, HealthStatus> {
        Box::pin(HealthContributor::check(self))
    }
}

/// Individual component health status within a health check response.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
}

impl ComponentHealth {
    /// Create a `ComponentHealth` for the named component with the given status.
    #[must_use]
    pub fn new(name: impl Into<String>, status: HealthStatus) -> Self {
        Self {
            name: name.into(),
            status,
        }
    }
}

/// Application build metadata for the health check response.
/// Pass an instance to [`HealthPlugin::app_info`] when registering the
/// plugin so `/health` reports the running binary's version, build
/// date, and git SHA.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AppBuildInfo {
    pub version: String,
    pub build_date: String,
    pub git_sha: String,
}

impl AppBuildInfo {
    /// Create an `AppBuildInfo` from version, build date, and git SHA strings.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        build_date: impl Into<String>,
        git_sha: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            build_date: build_date.into(),
            git_sha: git_sha.into(),
        }
    }
}

/// JSON response body for the `/healthcheck` endpoint.
/// Includes build-time metadata for deployment verification.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ServiceStatus {
    pub status: String,
    pub version: String,
    pub build_date: String,
    pub pkg_version: &'static str,
    pub rustc_version: &'static str,
    pub rustc_profile: &'static str,
    pub hostname: String,
    pub uptime_seconds: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<ComponentHealth>,
}

static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn get_hostname() -> &'static str {
    HOSTNAME.get_or_init(|| {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

/// Build timestamp baked into the binary, preferring
/// `SOURCE_DATE_EPOCH` when the build environment supplied it
/// (Debian, Nix, Bazel, GitHub Actions release tooling). Falls back
/// to the `built` crate's wall-clock timestamp so non-reproducible
/// dev builds still report *something* meaningful.
///
/// Read once at startup so the runtime path is a single static
/// load — `/health` is called frequently, and we don't want to pay
/// to re-format the epoch on every request.
fn baked_build_time() -> &'static str {
    use std::sync::OnceLock;
    static BUILD_TIME: OnceLock<String> = OnceLock::new();
    BUILD_TIME.get_or_init(|| {
        option_env!("GASKET_BUILD_TIME_EPOCH").map_or_else(
            || crate::built_info::BUILT_TIME_UTC.to_owned(),
            |epoch| format!("@{epoch}"),
        )
    })
}

fn service_status_base(app_info: Option<&AppBuildInfo>) -> ServiceStatus {
    let start = START_TIME.get_or_init(std::time::Instant::now);
    let uptime = start.elapsed().as_secs();
    let hostname = get_hostname().to_string();

    match app_info {
        Some(info) => ServiceStatus {
            status: "ok".to_string(),
            version: info.version.clone(),
            build_date: info.build_date.clone(),
            pkg_version: crate::built_info::PKG_VERSION,
            rustc_version: crate::built_info::RUSTC_VERSION,
            rustc_profile: crate::built_info::PROFILE,
            hostname,
            uptime_seconds: uptime,
            components: Vec::new(),
        },
        None => ServiceStatus {
            status: "ok".to_string(),
            version: crate::built_info::GIT_COMMIT_HASH_SHORT
                .unwrap_or("unknown")
                .to_string(),
            build_date: baked_build_time().to_owned(),
            pkg_version: crate::built_info::PKG_VERSION,
            rustc_version: crate::built_info::RUSTC_VERSION,
            rustc_profile: crate::built_info::PROFILE,
            hostname,
            uptime_seconds: uptime,
            components: Vec::new(),
        },
    }
}

/// Shared state for the healthcheck endpoint containing registered contributors.
#[derive(Clone, Default)]
struct HealthState {
    contributors: Arc<Vec<Arc<dyn ErasedHealthContributor>>>,
    app_info: Option<AppBuildInfo>,
}

/// Maximum time a single [`HealthContributor::check`] can take before
/// the framework forces its result to `HealthStatus::Error`. Prevents
/// one hung dependency (e.g. a Postgres ping waiting on a stuck
/// connection) from making the whole liveness probe block indefinitely.
pub const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn healthcheck_with_contributors(
    axum::extract::State(state): axum::extract::State<HealthState>,
) -> impl IntoResponse {
    let mut status = service_status_base(state.app_info.as_ref());

    // Check all contributors concurrently to avoid latency stacking; each
    // check is independently bounded so one stuck contributor cannot stall
    // the probe.
    let checks: Vec<_> = state
        .contributors
        .iter()
        .map(|c| {
            let c = Arc::clone(c);
            async move {
                let name = c.name().to_string();
                let status = tokio::time::timeout(HEALTH_CHECK_TIMEOUT, c.check())
                    .await
                    .unwrap_or(HealthStatus::Error);
                (name, status)
            }
        })
        .collect();
    let results = futures_util::future::join_all(checks).await;

    let mut overall = HealthStatus::Healthy;
    for (name, component_status) in results {
        // Spell out every variant so adding a new `HealthStatus` value
        // forces a deliberate decision here instead of silently
        // falling into a wildcard arm — `#[non_exhaustive]` only
        // catches that across crate boundaries.
        match component_status {
            HealthStatus::Error => overall = HealthStatus::Error,
            HealthStatus::Degraded if !matches!(overall, HealthStatus::Error) => {
                overall = HealthStatus::Degraded;
            }
            HealthStatus::Degraded | HealthStatus::Healthy => {}
        }
        status
            .components
            .push(ComponentHealth::new(name, component_status));
    }

    status.status = match overall {
        HealthStatus::Healthy => "ok".to_string(),
        HealthStatus::Degraded => "degraded".to_string(),
        HealthStatus::Error => "error".to_string(),
    };

    let http_status = match overall {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Error => StatusCode::SERVICE_UNAVAILABLE,
    };

    (http_status, Json(status))
}

async fn livez() -> impl IntoResponse {
    StatusCode::OK
}

/// Health check plugin that wires up registered `HealthContributor`s.
///
/// Contributors are registered via `add_contributor()` before building
/// the app. The `/healthcheck` endpoint aggregates their status.
#[derive(Default)]
pub struct HealthPlugin {
    contributors: Vec<Arc<dyn ErasedHealthContributor>>,
    app_info: Option<AppBuildInfo>,
}

impl std::fmt::Debug for HealthPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthPlugin")
            .field(
                "contributors",
                &self
                    .contributors
                    .iter()
                    .map(|c| c.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl HealthPlugin {
    /// Set application build info for the health check response.
    /// Without this, the health check returns the framework's build metadata.
    #[must_use]
    pub fn app_info(mut self, info: AppBuildInfo) -> Self {
        self.app_info = Some(info);
        self
    }

    /// Register a health contributor (chainable).
    pub fn contributor(mut self, contributor: impl HealthContributor) -> Self {
        self.contributors.push(Arc::new(contributor));
        self
    }

    /// Register a health contributor (mutable, for non-builder usage).
    pub fn add_contributor(&mut self, contributor: impl HealthContributor) {
        self.contributors.push(Arc::new(contributor));
    }
}

impl Plugin for HealthPlugin {
    fn name(&self) -> &'static str {
        "gasket:health"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().first()
    }

    fn routes(&self, _ctx: &RouteContext) -> Vec<TaggedRoute> {
        let bare_routes = Router::new().route("/livez", get(livez));

        let health_state = HealthState {
            contributors: Arc::new(self.contributors.clone()),
            app_info: self.app_info.clone(),
        };

        let public_routes = Router::new()
            .route("/healthcheck", get(healthcheck_with_contributors))
            .with_state(health_state);

        vec![
            TaggedRoute::new(RouteGroup::Bare, bare_routes),
            TaggedRoute::new(RouteGroup::Public, public_routes),
        ]
    }
}
