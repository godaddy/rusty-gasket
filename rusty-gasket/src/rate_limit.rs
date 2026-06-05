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

    /// The socket peer IP from [`ConnectInfo`](axum::extract::ConnectInfo), if
    /// present. This is the address of whoever opened the TCP connection — the
    /// reverse proxy / load balancer when one sits in front of the service.
    fn connect_info_ip(parts: &http::request::Parts) -> Option<String> {
        parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
    }

    /// Parse a single `X-Forwarded-For` entry into a canonical IP string.
    /// Accepts a bare `IpAddr` (IPv4 or IPv6) or an `ip:port` / `[ipv6]:port`
    /// form, returning the IP without the port. Returns `None` for anything
    /// that is not a valid address, so a malformed or forged entry triggers the
    /// caller's safe fallback rather than becoming a bogus rate-limit key.
    fn parse_forwarded_ip(raw: &str) -> Option<String> {
        let raw = raw.trim();
        if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            return Some(ip.to_string());
        }
        if let Ok(sa) = raw.parse::<std::net::SocketAddr>() {
            return Some(sa.ip().to_string());
        }
        None
    }

    /// Rate limit by the socket peer IP (from `ConnectInfo`).
    ///
    /// Note: behind a reverse proxy or load balancer this is the *proxy's*
    /// address, so every caller collapses into one bucket. Use
    /// [`ForwardedIpKey`] when the service runs behind a trusted proxy.
    #[derive(Debug, Clone)]
    pub struct IpAddressKey;

    impl RateLimitKey for IpAddressKey {
        fn extract_key(&self, parts: &http::request::Parts) -> Option<String> {
            connect_info_ip(parts)
        }
    }

    /// Rate limit by the real client IP read from the `X-Forwarded-For` header.
    ///
    /// Behind a reverse proxy / load balancer (e.g. an AWS ALB) the socket peer
    /// seen via [`ConnectInfo`](axum::extract::ConnectInfo) is the *proxy*, so
    /// [`IpAddressKey`] would collapse every caller into a single global bucket.
    /// This key instead reads the client address the proxy recorded in
    /// `X-Forwarded-For`.
    ///
    /// # Trusting the header
    ///
    /// `X-Forwarded-For` is a comma-separated, oldest-first list: each proxy
    /// *appends* the address it received the connection from, so the right-most
    /// entries are added by infrastructure you control and the left-most entries
    /// are whatever the original client sent — fully spoofable. Taking the
    /// left-most entry would let any caller forge their rate-limit key and evade
    /// the limit.
    ///
    /// So this key takes the entry `trusted_hops` positions **from the right**,
    /// where `trusted_hops` is the number of trusted proxies between this service
    /// and the public internet (`1` for a single ALB / ingress). With
    /// `trusted_hops == 1` it takes the last entry — the address the trusted
    /// proxy observed as the client. If the header is absent, has fewer than
    /// `trusted_hops` entries, or the selected entry is not a valid IP, it falls
    /// back to the `ConnectInfo` peer (the proxy itself): coarse, but never
    /// spoofable.
    ///
    /// `trusted_hops` must match the deployment — too low trusts a hop you do not
    /// control (spoofable); too high always falls back to the proxy IP (one
    /// global bucket). It cannot compensate for a proxy that forwards a
    /// client-supplied `X-Forwarded-For` verbatim instead of appending.
    #[derive(Debug, Clone)]
    pub struct ForwardedIpKey {
        trusted_hops: usize,
    }

    impl ForwardedIpKey {
        /// Build a key that trusts `trusted_hops` proxies in front of the
        /// service (reads the right-most `trusted_hops`-th `X-Forwarded-For`
        /// entry). `trusted_hops` is clamped to at least 1.
        #[must_use]
        pub fn new(trusted_hops: usize) -> Self {
            Self {
                trusted_hops: trusted_hops.max(1),
            }
        }
    }

    /// Defaults to a single trusted proxy (one ALB / ingress in front).
    impl Default for ForwardedIpKey {
        fn default() -> Self {
            Self::new(1)
        }
    }

    impl RateLimitKey for ForwardedIpKey {
        fn extract_key(&self, parts: &http::request::Parts) -> Option<String> {
            // All `X-Forwarded-For` values, in header order, flattened into one
            // oldest-first list: "client, proxy1, proxy2, ...".
            let xff = http::HeaderName::from_static("x-forwarded-for");
            let entries: Vec<&str> = parts
                .headers
                .get_all(&xff)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            // Take the entry `trusted_hops` from the right (the address the
            // closest trusted proxy observed). Left entries are client-spoofable.
            // Anything anomalous falls back to the socket peer.
            entries
                .len()
                .checked_sub(self.trusted_hops)
                .and_then(|idx| entries.get(idx))
                .and_then(|candidate| parse_forwarded_ip(candidate))
                .or_else(|| connect_info_ip(parts))
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
        #![allow(clippy::unwrap_used, clippy::panic)]

        use super::*;

        use std::net::SocketAddr;

        /// Build request `Parts` with the given `X-Forwarded-For` header values
        /// (each may itself be a comma-separated list) and an optional socket
        /// peer in `ConnectInfo`.
        fn parts_with(xff: &[&str], peer: Option<SocketAddr>) -> http::request::Parts {
            let mut builder = http::Request::builder();
            for v in xff {
                builder = builder.header("x-forwarded-for", *v);
            }
            let mut req = builder.body(()).unwrap();
            if let Some(p) = peer {
                req.extensions_mut().insert(axum::extract::ConnectInfo(p));
            }
            req.into_parts().0
        }

        fn peer(s: &str) -> SocketAddr {
            s.parse().unwrap()
        }

        #[test]
        fn forwarded_key_takes_rightmost_entry_for_single_hop() {
            // One trusted proxy (the ALB): the last entry is the address the ALB
            // saw; the left entry is client-supplied and must be ignored.
            let parts = parts_with(&["1.2.3.4, 5.6.7.8"], Some(peer("10.0.0.1:443")));
            assert_eq!(
                ForwardedIpKey::default().extract_key(&parts).as_deref(),
                Some("5.6.7.8")
            );
        }

        #[test]
        fn forwarded_key_ignores_spoofed_left_entries() {
            // A forged left-most entry must not become the key.
            let parts = parts_with(&["evil-spoof, 9.9.9.9"], Some(peer("10.0.0.1:443")));
            assert_eq!(
                ForwardedIpKey::default().extract_key(&parts).as_deref(),
                Some("9.9.9.9")
            );
        }

        #[test]
        fn forwarded_key_multi_hop_skips_trusted_proxies() {
            // Two trusted proxies (CDN + ALB): skip the two right-most entries
            // they added and take the client address (index len - 2).
            let parts = parts_with(&["evil, 203.0.113.7, 10.0.0.1"], Some(peer("10.0.0.2:443")));
            assert_eq!(
                ForwardedIpKey::new(2).extract_key(&parts).as_deref(),
                Some("203.0.113.7")
            );
        }

        #[test]
        fn forwarded_key_flattens_multiple_headers() {
            // Multiple X-Forwarded-For headers concatenate oldest-first.
            let parts = parts_with(&["1.1.1.1", "2.2.2.2, 3.3.3.3"], Some(peer("10.0.0.1:1")));
            assert_eq!(
                ForwardedIpKey::default().extract_key(&parts).as_deref(),
                Some("3.3.3.3")
            );
        }

        #[test]
        fn forwarded_key_falls_back_to_peer_when_header_absent() {
            let parts = parts_with(&[], Some(peer("192.0.2.5:1234")));
            assert_eq!(
                ForwardedIpKey::default().extract_key(&parts).as_deref(),
                Some("192.0.2.5")
            );
        }

        #[test]
        fn forwarded_key_falls_back_when_fewer_entries_than_trusted_hops() {
            // Expected 3 trusted proxies but only one entry present — anomalous,
            // so fall back to the socket peer rather than trusting it.
            let parts = parts_with(&["8.8.8.8"], Some(peer("10.0.0.9:80")));
            assert_eq!(
                ForwardedIpKey::new(3).extract_key(&parts).as_deref(),
                Some("10.0.0.9")
            );
        }

        #[test]
        fn forwarded_key_falls_back_on_malformed_selected_entry() {
            let parts = parts_with(&["1.2.3.4, not-an-ip"], Some(peer("10.0.0.2:80")));
            assert_eq!(
                ForwardedIpKey::default().extract_key(&parts).as_deref(),
                Some("10.0.0.2")
            );
        }

        #[test]
        fn forwarded_key_accepts_ipv6_and_ip_port_forms() {
            let v6 = parts_with(&["[2001:db8::1]:443"], None);
            assert_eq!(
                ForwardedIpKey::default().extract_key(&v6).as_deref(),
                Some("2001:db8::1")
            );
            let v4_port = parts_with(&["1.1.1.1, 9.9.9.9:8080"], None);
            assert_eq!(
                ForwardedIpKey::default().extract_key(&v4_port).as_deref(),
                Some("9.9.9.9")
            );
        }

        #[test]
        fn forwarded_key_none_without_header_or_peer() {
            // No header and no ConnectInfo → no key → middleware skips limiting.
            let parts = parts_with(&[], None);
            assert_eq!(ForwardedIpKey::default().extract_key(&parts), None);
        }

        #[test]
        fn new_clamps_zero_trusted_hops_to_one() {
            // 0 would underflow the right-index math; clamp to a single hop.
            let parts = parts_with(&["1.2.3.4, 5.6.7.8"], None);
            assert_eq!(
                ForwardedIpKey::new(0).extract_key(&parts).as_deref(),
                Some("5.6.7.8")
            );
        }

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
