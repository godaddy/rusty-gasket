//! Structured request logging middleware and tracing initialization.
//!
//! Creates a root tracing span per request containing method, path,
//! request ID, timing, status, and auth fields. Auth fields are filled
//! in by the auth middleware via the shared [`LoggingContext`] (the
//! bidirectional middleware communication pattern).

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::{Instrument, info_span};
use uuid::Uuid;

use super::request_id::{CURRENT_REQUEST_ID, RequestId, X_REQUEST_ID};
use crate::config::Environment;

/// Auth fields that the auth middleware writes back into the logging span.
/// Part of the bidirectional middleware communication pattern.
///
/// Marked `#[non_exhaustive]` because the framework may add new fields
/// (e.g. `tenant_id`, `mfa_status`) without breaking downstream consumers
/// who only read the existing fields. Build with [`AuthSummary::builder`];
/// read fields via the accessor methods. Direct field access is
/// crate-private so an `&mut AuthSummary` cannot be used to forge
/// values after construction.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AuthSummary {
    /// OAuth or API key client identifier.
    ///
    /// `Cow<'static, str>` so static placeholders like `""` or
    /// `"unknown"` don't heap-allocate on every protected request, but
    /// owned subject strings from a backend still work.
    pub(crate) client_id: Cow<'static, str>,
    /// Remote IP address (from forwarding headers or connection info).
    pub(crate) client_ip: Cow<'static, str>,
    /// Authenticated user or service subject.
    pub(crate) user_id: Cow<'static, str>,
    /// Name of the authentication method that produced this identity (e.g., "jwt", "api-key").
    pub(crate) auth_method: Cow<'static, str>,
    /// Outcome string (e.g., "authenticated:jwt", "anonymous", "failed:expired").
    pub(crate) auth_result: Cow<'static, str>,
    /// Whether the caller has elevated/superuser privileges.
    pub(crate) is_privileged: bool,
}

impl AuthSummary {
    /// Start building an [`AuthSummary`]. Required because the struct
    /// is `#[non_exhaustive]` with private fields — downstream crates
    /// cannot construct it any other way.
    pub fn builder() -> AuthSummaryBuilder {
        AuthSummaryBuilder(Self::default())
    }

    /// OAuth or API-key client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    /// Remote IP address (forwarding header or connection info).
    #[must_use]
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }
    /// Authenticated user or service subject.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    /// Name of the authentication method that produced this identity.
    #[must_use]
    pub fn auth_method(&self) -> &str {
        &self.auth_method
    }
    /// Outcome string (e.g. `"authenticated:jwt"`).
    #[must_use]
    pub fn auth_result(&self) -> &str {
        &self.auth_result
    }
    /// Whether the caller has elevated privileges.
    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        self.is_privileged
    }
}

/// Builder for [`AuthSummary`]. All setters take
/// `impl Into<Cow<'static, str>>` so callers can pass `&'static str`
/// (cheap borrow) or `String` (owned) without ceremony.
#[derive(Debug, Default)]
#[must_use = "AuthSummaryBuilder does nothing until `.build()` is called"]
pub struct AuthSummaryBuilder(AuthSummary);

impl AuthSummaryBuilder {
    /// Set the OAuth or API key client identifier.
    pub fn client_id(mut self, v: impl Into<Cow<'static, str>>) -> Self {
        self.0.client_id = v.into();
        self
    }
    /// Set the remote IP address.
    pub fn client_ip(mut self, v: impl Into<Cow<'static, str>>) -> Self {
        self.0.client_ip = v.into();
        self
    }
    /// Set the authenticated subject.
    pub fn user_id(mut self, v: impl Into<Cow<'static, str>>) -> Self {
        self.0.user_id = v.into();
        self
    }
    /// Set the authentication method label.
    pub fn auth_method(mut self, v: impl Into<Cow<'static, str>>) -> Self {
        self.0.auth_method = v.into();
        self
    }
    /// Set the outcome label.
    pub fn auth_result(mut self, v: impl Into<Cow<'static, str>>) -> Self {
        self.0.auth_result = v.into();
        self
    }
    /// Mark the caller as privileged.
    pub const fn privileged(mut self, v: bool) -> Self {
        self.0.is_privileged = v;
        self
    }
    /// Finish and yield the [`AuthSummary`].
    #[must_use]
    pub fn build(self) -> AuthSummary {
        self.0
    }
}

/// Shared context that bridges the logging and auth middleware.
///
/// The logging middleware creates this and inserts it into request
/// extensions. The auth middleware writes auth fields into it.
/// After the response, the logging middleware reads them back to
/// record in the tracing span. This avoids coupling the two
/// middleware directly while ensuring auth info appears in logs.
///
/// The auth summary is set at most once per request (the contract is
/// that the auth middleware runs once per request, before the logging
/// middleware reads it back), so this is implemented with [`OnceLock`]
/// rather than `Mutex<Option<_>>`.
#[derive(Clone, Default)]
pub struct LoggingContext {
    inner: Arc<OnceLock<AuthSummary>>,
}

impl std::fmt::Debug for LoggingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoggingContext").finish_non_exhaustive()
    }
}

impl LoggingContext {
    /// Create a new, empty logging context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store the auth summary so the logging middleware can read it after
    /// the response. Only the first call has effect — subsequent calls are
    /// silently ignored, matching the auth-middleware-runs-once contract.
    pub fn set(&self, summary: AuthSummary) {
        drop(self.inner.set(summary));
    }

    /// Borrow the auth summary, if one was set.
    #[must_use]
    pub fn get(&self) -> Option<&AuthSummary> {
        self.inner.get()
    }
}

/// Max length for externally-provided request IDs to prevent abuse.
const MAX_REQUEST_ID_LEN: usize = 128;

fn is_valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_REQUEST_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn get_or_generate_request_id(headers: &http::HeaderMap) -> String {
    headers
        .get(X_REQUEST_ID)
        .and_then(|h| h.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map_or_else(|| Uuid::now_v7().to_string(), ToString::to_string)
}

fn detect_env() -> &'static str {
    static ENV: OnceLock<String> = OnceLock::new();
    ENV.get_or_init(|| {
        std::env::var("GASKET_ENV")
            .or_else(|_| std::env::var("DEPLOYMENT_ENV"))
            .unwrap_or_else(|_| "local".to_string())
    })
}

/// Axum middleware that creates a root tracing span per request.
///
/// Generates or propagates a request ID, records method/path/user-agent,
/// and after the response completes, records status, duration, and any
/// auth fields written by the auth middleware via [`LoggingContext`].
pub async fn logging_middleware(mut request: Request, next: Next) -> Response {
    let start = Instant::now();

    let request_id = get_or_generate_request_id(request.headers());
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unknown".to_string(), |mp| mp.as_str().to_string());

    let logging_ctx = LoggingContext::new();
    request.extensions_mut().insert(logging_ctx.clone());
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let user_agent = request
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let span = info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path,
        matched_path = %matched_path,
        client_id = tracing::field::Empty,
        client_ip = tracing::field::Empty,
        user_id = tracing::field::Empty,
        auth_method = tracing::field::Empty,
        auth_result = tracing::field::Empty,
        is_privileged = tracing::field::Empty,
        status = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        env = %detect_env(),
        user_agent = %user_agent,
    );

    let mut response = CURRENT_REQUEST_ID
        .scope(request_id.clone(), async { next.run(request).await })
        .instrument(span.clone())
        .await;

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, header_value);
    }

    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status = response.status().as_u16();

    if let Some(c) = logging_ctx.get() {
        // AsRef for Cow gives us a &str without depending on the
        // unstable `Cow::as_str` shortcut.
        span.record("client_id", c.client_id.as_ref());
        span.record("client_ip", c.client_ip.as_ref());
        span.record("user_id", c.user_id.as_ref());
        span.record("auth_method", c.auth_method.as_ref());
        span.record("auth_result", c.auth_result.as_ref());
        span.record("is_privileged", c.is_privileged);
    }
    span.record("status", status);
    span.record("duration_ms", duration_ms);

    tracing::info!(parent: &span, "request completed");

    response
}

/// Initialize tracing by detecting the environment from `GASKET_ENV`.
///
/// Convenience wrapper around [`init_tracing`] that reads the environment
/// automatically. Use this in `main()` when you don't need to control
/// the environment explicitly.
pub fn init_tracing_from_env() {
    let env_str = std::env::var("GASKET_ENV").unwrap_or_else(|_| "local".to_string());
    let env: Environment =
        serde_json::from_value(serde_json::Value::String(env_str)).unwrap_or(Environment::Local);
    init_tracing(env);
}

/// Initialize the global tracing subscriber based on the deployment environment.
///
/// - **Local**: pretty-printed, human-readable output
/// - **Non-local**: compact or JSON format (JSON when the `json-log` feature is enabled)
///
/// Respects `RUST_LOG` / `tracing` `EnvFilter` for level control.
///
/// For OTEL-enabled deployments, use `init_tracing_with_otel` (available
/// behind the `otlp` feature) instead, which sets up a dual-layer subscriber
/// (fmt + OTEL) with independent filters.
pub fn init_tracing(env: Environment) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    match env {
        Environment::Local => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .pretty();
            registry.with(fmt_layer).init();
        }
        _ => {
            #[cfg(feature = "json-log")]
            {
                let fmt_layer = tracing_subscriber::fmt::layer().json().with_target(true);
                registry.with(fmt_layer).init();
            }
            #[cfg(not(feature = "json-log"))]
            {
                let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
                registry.with(fmt_layer).init();
            }
        }
    }
}

/// Initialize a dual-layer tracing subscriber with both a fmt layer for
/// structured logs and an OpenTelemetry layer for span/metric export.
///
/// A single shared `EnvFilter` controls both layers; the default fallback
/// silences noisy low-level crates (hyper, rustls, tonic, h2) when
/// `RUST_LOG` is unset. For independent per-layer filtering, build the
/// `tracing-subscriber` registry directly.
///
/// This is the production-recommended setup when OTEL is enabled. The
/// typical call sequence is:
///
/// ```no_run
/// # #[cfg(feature = "otlp")]
/// # async fn example() {
/// let guard = rusty_gasket::otel::try_init("my-service", "0.1.0", "production");
/// if let Some(Ok(guard)) = guard
///     && let Some(tracer) = guard.tracer_provider()
/// {
///     rusty_gasket::observability::init_tracing_with_otel(
///         rusty_gasket::config::Environment::Production,
///         tracer,
///         "my-service",
///     );
///     // Hold the guard until the end of main, then explicitly call
///     // `guard.shutdown().await` so the blocking flush runs on a
///     // spawn_blocking thread instead of the runtime worker.
/// }
/// # }
/// ```
#[cfg(feature = "otlp")]
pub fn init_tracing_with_otel(
    env: Environment,
    provider: &opentelemetry_sdk::trace::SdkTracerProvider,
    service_name: &'static str,
) {
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    // Single global filter controlling both layers. For independent per-layer
    // filtering, use the `tracing-subscriber` registry directly.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,h2=off,hyper=off,rustls=off,tonic=off"));

    let tracer = provider.tracer(service_name);
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let registry = tracing_subscriber::registry().with(filter).with(otel_layer);

    match env {
        Environment::Local => {
            let fmt_layer = tracing_subscriber::fmt::layer().with_target(true).pretty();
            registry.with(fmt_layer).init();
        }
        _ => {
            #[cfg(feature = "json-log")]
            {
                let fmt_layer = tracing_subscriber::fmt::layer().json().with_target(true);
                registry.with(fmt_layer).init();
            }
            #[cfg(not(feature = "json-log"))]
            {
                let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
                registry.with(fmt_layer).init();
            }
        }
    }
}
