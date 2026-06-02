//! Authentication and authorization error types.
//!
//! [`AuthError`] covers all failure modes across the auth chain: missing
//! credentials, invalid tokens, and backend errors. Each variant maps to
//! an appropriate HTTP status code (401 or 403 for client errors, 500 for
//! backend/configuration failures).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rusty_gasket::error::ApiError as _;

/// Error type for authentication and authorization failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No credentials were provided (no header, cookie, or parameter found).
    #[error("Missing credentials: {0}")]
    MissingCredentials(String),

    /// Credentials were present but invalid (wrong password, revoked key, etc.).
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    /// JWT `exp` claim is in the past.
    #[error("Token expired")]
    TokenExpired,

    /// JWT signature, audience, issuer, or structure validation failed.
    #[error("Token validation failed: {0}")]
    TokenValidation(String),

    /// Authorization policy explicitly denied the request.
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    /// An internal error in the auth backend (database failure, network timeout, etc.).
    #[error("Backend error: {0}")]
    BackendError(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Misconfiguration detected at startup or runtime (missing key, bad issuer URL, etc.).
    #[error("Configuration error: {0}")]
    Configuration(String),
}

impl rusty_gasket::error::ApiError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingCredentials(_)
            | Self::InvalidCredentials(_)
            | Self::TokenExpired
            | Self::TokenValidation(_) => StatusCode::UNAUTHORIZED,
            Self::AuthorizationDenied(_) => StatusCode::FORBIDDEN,
            Self::BackendError(_) | Self::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &str {
        match self {
            Self::MissingCredentials(_) => "MISSING_CREDENTIALS",
            Self::InvalidCredentials(_) => "INVALID_CREDENTIALS",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenValidation(_) => "TOKEN_VALIDATION_FAILED",
            Self::AuthorizationDenied(_) => "AUTHORIZATION_DENIED",
            Self::BackendError(_) => "AUTH_BACKEND_ERROR",
            Self::Configuration(_) => "AUTH_CONFIGURATION_ERROR",
        }
    }
}

impl AuthError {
    /// A stable, bounded label suitable for structured logging fields.
    ///
    /// Unlike `to_string()`, this never includes attacker-controlled or
    /// token-derived substrings, so the value is safe to emit in
    /// fixed-cardinality analytics fields.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MissingCredentials(_) => "missing_credentials",
            Self::InvalidCredentials(_) => "invalid_credentials",
            Self::TokenExpired => "token_expired",
            Self::TokenValidation(_) => "token_validation",
            Self::AuthorizationDenied(_) => "authorization_denied",
            Self::BackendError(_) => "backend_error",
            Self::Configuration(_) => "configuration_error",
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let request_id = rusty_gasket::observability::current_request_id().unwrap_or_default();

        let message = if status.is_client_error() {
            tracing::warn!(request_id = %request_id, error = %self, "Auth client error");
            // Spell out every variant: a new `AuthError` value should
            // force a deliberate choice of client-facing message, not
            // silently fall into a generic "Authentication failed"
            // wildcard. The server-error path below is `else`-only
            // (5xx variants are listed by exclusion in `status_code`).
            match self {
                Self::MissingCredentials(_) => "Missing credentials",
                Self::InvalidCredentials(_) => "Invalid credentials",
                Self::TokenExpired => "Token expired",
                Self::TokenValidation(_) => "Token validation failed",
                Self::AuthorizationDenied(_) => "Authorization denied",
                Self::BackendError(_) | Self::Configuration(_) => "Authentication failed",
            }
        } else {
            tracing::error!(request_id = %request_id, error = %self, "Auth backend error");
            "Internal authentication error"
        };

        rusty_gasket::error::quick_error_response(status, self.error_code(), message)
    }
}

#[cfg(test)]
mod tests {
    use super::AuthError;

    #[test]
    fn category_is_bounded_and_never_includes_inner_string() {
        // The middleware emits `auth_result = format!("failed:{category}")`
        // as a structured analytics field. Verify each variant maps to a
        // small fixed label that never embeds the inner String (which can
        // hold attacker-controlled substrings).
        let probes = [
            AuthError::MissingCredentials("kid=evil-injected".to_string()),
            AuthError::InvalidCredentials("expected; DROP TABLE".to_string()),
            AuthError::TokenExpired,
            AuthError::TokenValidation("sig mismatch for kid=abc".to_string()),
            AuthError::AuthorizationDenied("scope missing".to_string()),
            AuthError::Configuration("bad audience".to_string()),
        ];
        let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for err in &probes {
            let cat = err.category();
            assert!(
                cat.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "category '{cat}' is not snake_case ASCII"
            );
            assert!(
                !cat.contains("evil-injected") && !cat.contains("kid="),
                "category leaks inner string: {cat}"
            );
            seen.insert(cat);
        }
        assert_eq!(seen.len(), probes.len(), "categories must be distinct");
    }
}
