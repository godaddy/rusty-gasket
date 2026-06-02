//! Request-scoped authentication context.
//!
//! Populated by the auth middleware and inserted into axum request
//! extensions for downstream handlers and extractors.

use rusty_gasket::auth::Identity;

/// Request-scoped authentication context populated by the auth middleware.
///
/// Inserted into axum request extensions so downstream handlers and
/// middleware can access the caller's identity without re-authenticating.
#[derive(Debug, Clone)]
pub struct AuthContext {
    identity: Option<Identity>,
    client_ip: String,
    request_id: String,
    auth_result: AuthResult,
}

impl AuthContext {
    /// Create a new auth context (used by the auth middleware).
    pub(crate) const fn new(
        identity: Option<Identity>,
        client_ip: String,
        request_id: String,
        auth_result: AuthResult,
    ) -> Self {
        Self {
            identity,
            client_ip,
            request_id,
            auth_result,
        }
    }

    /// The verified identity, if authentication succeeded.
    #[must_use]
    pub const fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Client IP extracted from connection info or forwarding headers.
    #[must_use]
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }

    /// Unique request identifier for tracing and audit correlation.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Summary of the authentication outcome.
    #[must_use]
    pub const fn auth_result(&self) -> &AuthResult {
        &self.auth_result
    }
}

/// Describes the outcome of an authentication attempt.
///
/// The `reason` carried by the `Failed` variant can include
/// attacker-controlled substrings (JWT `kid`, custom header values).
/// The [`std::fmt::Display`] impl deliberately omits it and emits only the
/// [`category`](Self::category) label so that any operator who pipes
/// `AuthResult` into a metrics field or analytics label gets a
/// bounded-cardinality string by default. Callers that genuinely need
/// the raw reason for debugging can read it via [`Self::failure_reason`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthResult {
    /// Caller was successfully authenticated via the named method.
    Authenticated { method: &'static str },

    /// No credentials were provided and the policy allows anonymous access.
    Anonymous,

    /// Authentication was attempted but failed. The reason is held in a
    /// private field; read it via [`AuthResult::failure_reason`]. This
    /// keeps attacker-controlled bytes out of the `Display` impl.
    Failed(FailedReason),
}

/// Opaque wrapper around the human-readable reason an authentication
/// attempt failed.
///
/// Constructed by the framework auth middleware. Read the underlying
/// string via [`Self::as_str`] when you actually want to log the full
/// reason; prefer [`AuthResult::category`] for any analytics field.
#[derive(Debug, Clone)]
pub struct FailedReason(String);

/// Maximum byte length of a [`FailedReason`] after sanitization. Long
/// enough for any reasonable backend error message (jsonwebtoken,
/// reqwest, internal `AuthError` chains usually < 200 bytes); short
/// enough to defeat a hostile caller who tries to amplify the audit
/// log by passing a header that gets echoed back into the reason
/// string.
const MAX_FAILED_REASON_LEN: usize = 512;

impl FailedReason {
    /// Wrap a failure reason string. Public so backend authors and
    /// tests can construct `AuthResult::Failed`; the security property
    /// we care about is the redacting `Display` impl, not construction
    /// restriction.
    ///
    /// Performs two safety steps on construction:
    ///
    /// 1. Strips ASCII control characters (including CR/LF) so a
    ///    hostile `kid` claim cannot inject a forged log line when
    ///    the reason is rendered through a non-JSON tracing
    ///    formatter.
    /// 2. Truncates to the framework's fixed failed-reason byte cap so an attacker
    ///    who controls a JWT header or custom header field cannot
    ///    amplify the audit log path into a memory-DoS vector.
    ///
    /// The original string is NOT preserved; once normalized, the
    /// sanitized form is what callers see via [`Self::as_str`].
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        let raw = reason.into();
        let mut sanitized = String::with_capacity(raw.len().min(MAX_FAILED_REASON_LEN));
        for ch in raw.chars() {
            if sanitized.len() + ch.len_utf8() > MAX_FAILED_REASON_LEN {
                break;
            }
            if !ch.is_control() {
                sanitized.push(ch);
            }
        }
        Self(sanitized)
    }

    /// Borrow the raw reason string. Operators MUST treat this as
    /// untrusted text (it can contain attacker-controlled substrings
    /// from a JWT header, cookie, or custom header value), though it
    /// is guaranteed to be no longer than the framework's fixed failed-reason cap
    /// bytes and free of ASCII control characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AuthResult {
    /// A stable, bounded label for the outcome of an authentication
    /// attempt — safe to use in metrics labels or fixed-cardinality
    /// structured logging fields.
    ///
    /// Unlike [`std::fmt::Display`], this never embeds the inner
    /// `reason` string of `Failed`.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Authenticated { .. } => "authenticated",
            Self::Anonymous => "anonymous",
            Self::Failed(_) => "failed",
        }
    }

    /// The raw failure reason, if this is a [`Self::Failed`] result.
    /// Returns `None` for other variants. Callers MUST treat the
    /// returned string as untrusted — see [`FailedReason::as_str`].
    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            Self::Failed(r) => Some(r.as_str()),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthResult {
    /// Emits only the bounded category label plus the `&'static str`
    /// method name for `Authenticated`. Never embeds attacker-controlled
    /// bytes — use [`AuthResult::failure_reason`] if you need them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated { method } => write!(f, "authenticated:{method}"),
            Self::Anonymous => f.write_str("anonymous"),
            Self::Failed(_) => f.write_str("failed"),
        }
    }
}
