//! Token-bucket rate limiting using the Governor crate.
//!
//! Provides per-client rate limiting with configurable key extraction
//! (by request ID, client IP, or custom), burst capacity, and exempt
//! keys for privileged callers.

/// Marker type inserted into request extensions to identify the rate
/// limit subject — typically the authenticated user's id, client id,
/// or API-key fingerprint.
///
/// Defined outside the feature-gated module so the auth middleware (in
/// `rusty-gasket-auth`) can populate it without taking a dependency on
/// the `rate-limit` feature. When `ClientIdKey` is used as the rate
/// limit extractor, this is the value it reads back out.
#[derive(Debug, Clone)]
pub struct RateLimitSubject(String);

/// Maximum byte length of a [`RateLimitSubject`]. The subject is keyed
/// into a `DashMap` inside the rate limiter; an attacker who can
/// influence the subject (e.g. JWT `sub` claim from a backend that
/// issues anonymous tokens) MUST NOT be able to grow the map without
/// bound by passing arbitrarily long strings. 256 bytes fits any
/// reasonable identifier (UUID, GUID, OIDC `sub`, hostname:port,
/// `client@tenant` composite) while bounding worst-case key memory.
const MAX_RATE_LIMIT_SUBJECT_LEN: usize = 256;

impl RateLimitSubject {
    /// Wrap the given subject string, truncating to a fixed cap so an
    /// attacker who controls a JWT claim or API key value cannot
    /// inflate the rate-limit map's per-key cost.
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        let mut s = subject.into();
        if s.len() > MAX_RATE_LIMIT_SUBJECT_LEN {
            // Truncate at a UTF-8 boundary so the resulting string
            // remains valid Rust UTF-8. `floor_char_boundary` is
            // stable as of 1.71 and lives in `std::str` for `&str`,
            // so use the `char_indices`-based fallback that works on
            // an owned String.
            let cut = (0..=MAX_RATE_LIMIT_SUBJECT_LEN)
                .rev()
                .find(|&i| s.is_char_boundary(i))
                .unwrap_or(0);
            s.truncate(cut);
        }
        Self(s)
    }

    /// Borrow the inner subject string. Guaranteed to be no longer
    /// than the framework's fixed rate-limit subject cap.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "rate-limit")]
mod inner {
    pub use super::RateLimitSubject;

    use std::collections::HashSet;
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::middleware::Next;
    use axum::response::{IntoResponse, Response};
    use governor::clock::{Clock, DefaultClock};
    use governor::middleware::NoOpMiddleware;
    use governor::state::keyed::DashMapStateStore;
    use serde::{Deserialize, Serialize};

    /// A keyed rate limiter backed by `DashMap` for concurrent access.
    /// Keys are strings (client ID, IP address, etc.).
    pub type KeyedRateLimiter =
        governor::RateLimiter<String, DashMapStateStore<String>, DefaultClock, NoOpMiddleware>;

    /// Owns the background cleanup task for a [`KeyedRateLimiter`] and aborts
    /// it when the last [`RateLimiter`] reference is dropped.
    ///
    /// The retain-recent loop is a `loop { interval.tick().await; ... }` that
    /// holds an `Arc<KeyedRateLimiter>`. Without `abort()`, the loop continues
    /// to run for the program lifetime even after the application has dropped
    /// every other reference to the limiter — leaking the limiter's `DashMap`.
    /// `Drop` here calls `JoinHandle::abort` so the task is canceled cooperatively.
    struct LimiterCleanup(tokio::task::JoinHandle<()>);

    impl Drop for LimiterCleanup {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Bundles a [`KeyedRateLimiter`] with the background task that evicts
    /// expired entries. The cleanup task is aborted when the last clone of
    /// this `RateLimiter` is dropped.
    ///
    /// Cloning is cheap — the limiter and cleanup guard are shared via `Arc`.
    #[derive(Clone)]
    pub struct RateLimiter {
        limiter: Arc<KeyedRateLimiter>,
        _cleanup: Arc<LimiterCleanup>,
    }

    impl std::fmt::Debug for RateLimiter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RateLimiter").finish_non_exhaustive()
        }
    }

    impl std::ops::Deref for RateLimiter {
        type Target = KeyedRateLimiter;
        fn deref(&self) -> &Self::Target {
            &self.limiter
        }
    }

    /// Rate limiting configuration. Can be loaded from the `"rate_limit"`
    /// config section or from environment variables via `from_env()`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RateLimitConfig {
        /// Whether rate limiting is active. Can be toggled via `RATE_LIMIT_ENABLED`.
        #[serde(default = "default_true")]
        pub enabled: bool,
        /// Sustained request rate per key (token refill rate).
        #[serde(default = "default_rpm")]
        pub requests_per_minute: NonZeroU32,
        /// Maximum burst above the sustained rate before throttling begins.
        #[serde(default = "default_burst")]
        pub burst_size: NonZeroU32,
        /// Keys that bypass rate limiting entirely (e.g., internal service accounts).
        #[serde(default)]
        pub exempt_keys: HashSet<String>,
    }

    const fn default_true() -> bool {
        true
    }
    const fn default_rpm() -> NonZeroU32 {
        NonZeroU32::new(60).expect("nonzero")
    }
    const fn default_burst() -> NonZeroU32 {
        NonZeroU32::new(10).expect("nonzero")
    }

    impl Default for RateLimitConfig {
        fn default() -> Self {
            Self {
                enabled: true,
                requests_per_minute: default_rpm(),
                burst_size: default_burst(),
                exempt_keys: HashSet::new(),
            }
        }
    }

    /// Parse the `RATE_LIMIT_ENABLED` env var value into a bool.
    ///
    /// Extracted as a pure function so the truthiness table can be
    /// exhaustively tested without mutating process-wide env state
    /// (which is unsafe under Rust 2024 edition).
    ///
    /// `None` (variable unset) → enabled. Any of `false`/`0`/`no`/`off`/
    /// `disabled` (case-insensitive, whitespace-tolerant) → disabled.
    /// Anything else → enabled.
    #[must_use]
    pub fn parse_enabled(raw: Option<&str>) -> bool {
        match raw {
            None => true,
            Some(v) => !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "false" | "0" | "no" | "off" | "disabled"
            ),
        }
    }

    impl RateLimitConfig {
        /// Load rate limit configuration from environment variables.
        ///
        /// - `RATE_LIMIT_ENABLED` — any of `false`, `0`, `no`, `off`,
        ///   `disabled` (case-insensitive) disables rate limiting; any
        ///   other value (or the variable being unset) enables it.
        /// - `RATE_LIMIT_REQUESTS_PER_MINUTE` — sustained rate (default: 60)
        /// - `RATE_LIMIT_BURST_SIZE` — burst capacity (default: 10)
        #[must_use]
        pub fn from_env() -> Self {
            let enabled = parse_enabled(std::env::var("RATE_LIMIT_ENABLED").ok().as_deref());
            let rpm = std::env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .and_then(NonZeroU32::new)
                .unwrap_or_else(default_rpm);
            let burst = std::env::var("RATE_LIMIT_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .and_then(NonZeroU32::new)
                .unwrap_or_else(default_burst);

            Self {
                enabled,
                requests_per_minute: rpm,
                burst_size: burst,
                exempt_keys: HashSet::new(),
            }
        }

        /// Construct the Governor rate limiter from this configuration.
        ///
        /// Spawns a background task that periodically evicts expired entries
        /// from the `DashMap` to prevent unbounded memory growth under attack.
        /// The returned [`RateLimiter`] owns the cleanup task — aborting it
        /// automatically when the last clone is dropped.
        #[must_use]
        pub fn build_limiter(&self) -> RateLimiter {
            let quota =
                governor::Quota::per_minute(self.requests_per_minute).allow_burst(self.burst_size);
            let limiter = Arc::new(governor::RateLimiter::dashmap(quota));

            let limiter_bg = Arc::clone(&limiter);
            let cleanup = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    // Wrap each pass in `catch_unwind` so a panic inside
                    // `retain_recent` (downcast bugs, allocator faults)
                    // doesn't silently kill the cleanup task and leak
                    // the DashMap forever. The rate-limit map would
                    // otherwise grow unbounded under attack with no
                    // visible signal.
                    let bg = Arc::clone(&limiter_bg);
                    let outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            bg.retain_recent()
                        }));
                    if let Err(payload) = outcome {
                        let msg = payload
                            .downcast_ref::<&'static str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("<non-string panic payload>");
                        tracing::error!(
                            panic = msg,
                            "rate-limit cleanup pass panicked; loop continues, map may grow",
                        );
                    }
                }
            });

            RateLimiter {
                limiter,
                _cleanup: Arc::new(LimiterCleanup(cleanup)),
            }
        }
    }

    /// Determines the rate limit key for a request.
    /// Return `None` to skip rate limiting for this request.
    pub trait RateLimitKey: Send + Sync + 'static {
        /// Extract the caller-specific key from request metadata.
        fn extract_key(&self, parts: &http::request::Parts) -> Option<String>;
    }

    /// Readable handle for a rate-limit key extraction strategy.
    ///
    /// The middleware stores strategies dynamically, but application and
    /// framework code should talk in terms of key extractors rather than
    /// `Arc<dyn ...>` plumbing.
    #[derive(Clone)]
    pub struct RateLimitKeyExtractor {
        /// Shared extraction strategy used by cloned middleware state.
        inner: Arc<dyn RateLimitKey>,
    }

    impl RateLimitKeyExtractor {
        /// Create a key extractor from a concrete strategy.
        #[must_use]
        pub fn new(strategy: impl RateLimitKey) -> Self {
            Self {
                inner: Arc::new(strategy),
            }
        }

        /// Extract the rate-limit key for a request.
        #[must_use]
        pub fn extract_key(&self, parts: &http::request::Parts) -> Option<String> {
            self.inner.extract_key(parts)
        }
    }

    impl std::fmt::Debug for RateLimitKeyExtractor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RateLimitKeyExtractor")
                .finish_non_exhaustive()
        }
    }

    /// Rate limit by authenticated client identity.
    /// Reads `RateLimitSubject` from request extensions (must be inserted by
    /// auth middleware or a custom layer before the rate limit middleware runs).
    #[derive(Debug, Clone)]
    pub struct ClientIdKey;

    impl RateLimitKey for ClientIdKey {
        fn extract_key(&self, parts: &http::request::Parts) -> Option<String> {
            parts
                .extensions
                .get::<RateLimitSubject>()
                .map(|s| s.0.clone())
        }
    }

    /// Rate limit by client IP address (from `ConnectInfo`).
    #[derive(Debug, Clone)]
    pub struct IpAddressKey;

    impl RateLimitKey for IpAddressKey {
        fn extract_key(&self, parts: &http::request::Parts) -> Option<String> {
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
        }
    }

    /// Shared state for the rate limit middleware.
    #[derive(Clone)]
    pub struct RateLimitState {
        /// The Governor rate limiter (with its owned cleanup task).
        pub limiter: RateLimiter,
        /// Current rate limit configuration (for checking exemptions and enabled state).
        pub config: RateLimitConfig,
        /// Strategy for extracting the rate limit key from each request.
        pub key_extractor: RateLimitKeyExtractor,
    }

    impl std::fmt::Debug for RateLimitState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RateLimitState")
                .field("config", &self.config)
                .finish_non_exhaustive()
        }
    }

    /// Axum middleware that enforces per-key rate limits.
    ///
    /// Extracts a key via the configured [`RateLimitKey`], checks the Governor
    /// limiter, and returns 429 Too Many Requests when the rate is exceeded.
    /// Exempt keys and requests with no extractable key are passed through.
    pub async fn rate_limit_middleware(
        axum::extract::State(state): axum::extract::State<Arc<RateLimitState>>,
        request: Request,
        next: Next,
    ) -> Response {
        if !state.config.enabled {
            return next.run(request).await;
        }

        let (parts, body) = request.into_parts();
        let key = state.key_extractor.extract_key(&parts);
        let request = Request::from_parts(parts, body);

        let key = match key {
            Some(k) => k,
            None => return next.run(request).await,
        };

        if state.config.exempt_keys.contains(&key) {
            return next.run(request).await;
        }

        match state.limiter.check_key(&key) {
            Ok(_) => next.run(request).await,
            Err(not_until) => {
                let clock = DefaultClock::default();
                let wait = not_until.wait_time_from(clock.now());
                let retry_after = wait.as_secs().saturating_add(1).to_string();

                let correlation_id = crate::observability::current_request_id()
                    .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                    .unwrap_or_else(uuid::Uuid::now_v7);

                let body = crate::error::ErrorResponse::new(
                    "RATE_LIMIT_EXCEEDED",
                    "Too many requests",
                    correlation_id,
                );

                let mut response =
                    (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
                if let Ok(val) = http::HeaderValue::from_str(&retry_after) {
                    response.headers_mut().insert("Retry-After", val);
                }
                response
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Verifies that dropping the public `RateLimiter` aborts the
        /// background cleanup task. We observe this through the Arc
        /// strong count on the inner limiter — when only the cleanup
        /// task is left, the count is 1; after abort, the count drops
        /// to 0 (but the Arc is gone, so we use Weak).
        #[tokio::test]
        async fn dropping_rate_limiter_aborts_cleanup_task() {
            let cfg = RateLimitConfig::default();
            let limiter = cfg.build_limiter();
            let weak = Arc::downgrade(&limiter.limiter);

            // While the limiter is alive, the cleanup task and the public
            // handle each hold a strong ref.
            assert!(weak.strong_count() >= 2);

            drop(limiter);

            // The cleanup task is async; abort + drop happens on the runtime.
            // Spin until weak.strong_count == 0 or we time out.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while weak.strong_count() != 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert_eq!(
                weak.strong_count(),
                0,
                "cleanup task did not release its Arc — abort was not effective"
            );
        }
    }
}

#[cfg(feature = "rate-limit")]
pub use inner::*;
