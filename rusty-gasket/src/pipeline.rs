//! Middleware pipeline slot ordering.
//!
//! Defines the fixed slots that middleware layers are assigned to,
//! ensuring consistent ordering (e.g., logging before auth, auth before
//! rate limiting) regardless of plugin registration order.

/// Ordered middleware pipeline slots.
///
/// Plugins tag their Tower layers with a slot; the server assembles
/// them in slot order regardless of plugin registration order. This
/// guarantees the correct middleware ordering (e.g., logging before auth,
/// auth before rate limiting, rate limiting before database transactions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MiddlewareSlot {
    /// Outermost: CORS, HSTS, compression, body size limits.
    TransportSecurity = 0,
    /// Request ID generation, tracing span creation, structured logging.
    Logging = 10,
    /// Authentication and authorization.
    Authentication = 20,
    /// Per-client or per-IP rate limiting.
    RateLimit = 30,
    /// Per-request database transaction with request ID correlation.
    Transaction = 40,
    /// Application-specific middleware (closest to handlers).
    Custom = 50,
}
