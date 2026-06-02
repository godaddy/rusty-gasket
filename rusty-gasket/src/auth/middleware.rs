//! Authentication middleware for axum.
//!
//! Runs the [`AuthChain`] against each request, populates [`AuthContext`]
//! in request extensions, writes auth summary into [`LoggingContext`] for
//! the observability layer, and optionally emits audit log events.

use std::borrow::Cow;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use rusty_gasket::observability::{AuthSummary, LoggingContext, RequestId};
use rusty_gasket::rate_limit::RateLimitSubject;

use rusty_gasket::auth::audit::{
    AuditLogger, AuditLoggerHandle, AuthAuditEvent, AuthAuditOutcome, IntoAuditLoggerHandle,
};
use rusty_gasket::auth::chain::AuthChain;
use rusty_gasket::auth::context::{AuthContext, AuthResult, FailedReason};
use rusty_gasket::auth::identity::Identity;

/// Shared state for the auth middleware layer.
///
/// Construct via [`Self::new`] (and optionally chain
/// [`Self::audit_logger`]); read the inner chain via [`Self::chain`].
/// Fields are crate-private so a downstream consumer who holds an
/// `&mut AuthMiddlewareState` can't swap in a different `AuthChain`
/// after the middleware has been mounted.
#[non_exhaustive]
pub struct AuthMiddlewareState {
    /// Ordered authentication backends used by the middleware.
    pub(crate) chain: AuthChain,
    /// Optional audit sink for recording authentication outcomes.
    pub(crate) audit_logger: Option<AuditLoggerHandle>,
}

impl AuthMiddlewareState {
    /// Create a state with the given chain and no audit logger.
    #[must_use]
    pub fn new(chain: AuthChain) -> Self {
        Self {
            chain,
            audit_logger: None,
        }
    }

    /// Attach an audit logger that will receive every auth event.
    #[must_use]
    pub fn with_audit_logger(mut self, logger: impl IntoAuditLoggerHandle) -> Self {
        // Accept concrete loggers and shared loggers at the boundary, then
        // store the normalized handle internally.
        self.audit_logger = Some(logger.into_audit_logger_handle());
        self
    }

    /// Attach an already-created audit logger handle.
    #[must_use]
    pub fn with_audit_logger_handle(mut self, logger: AuditLoggerHandle) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Deprecated builder name; use [`Self::with_audit_logger`].
    #[must_use]
    #[deprecated(note = "use `with_audit_logger` for consistency with other builders")]
    pub fn audit_logger(self, logger: Arc<dyn AuditLogger>) -> Self {
        self.with_audit_logger_handle(AuditLoggerHandle::shared(logger))
    }

    /// Borrow the inner auth chain.
    #[must_use]
    pub const fn chain(&self) -> &AuthChain {
        &self.chain
    }
}

impl std::fmt::Debug for AuthMiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMiddlewareState")
            .field("chain", &self.chain)
            .field("has_audit_logger", &self.audit_logger.is_some())
            .finish()
    }
}

/// Axum middleware that runs the `AuthChain` and injects `AuthContext`
/// into request extensions for downstream handlers.
///
/// Also populates the `LoggingContext` (if present in extensions) so the
/// observability layer can record auth fields in the root tracing span.
//
// No #[tracing::instrument] here: the root `http_request` span from the
// logging middleware already covers the request and the auth events
// emit their own structured fields. A second span per request would
// double the per-request span allocation cost on the hot path.
pub async fn auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let uri = request.uri();

    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();

    let client_ip = extract_client_ip(&request);

    let identity = match state.chain.authenticate(headers, uri).await {
        Ok(id) => id,
        Err(e) => {
            return handle_auth_failure(
                state.audit_logger.as_ref().map(AuditLoggerHandle::logger),
                &request,
                request_id,
                client_ip,
                e,
            );
        }
    };

    let identity_ref = identity.as_ref();
    audit_success_or_anonymous(
        state.audit_logger.as_ref().map(AuditLoggerHandle::logger),
        &request_id,
        &client_ip,
        identity_ref,
    );

    populate_logging_context(&request, build_success_summary(&client_ip, identity_ref));

    if let Some(id) = identity_ref {
        request
            .extensions_mut()
            .insert(RateLimitSubject::new(id.subject()));
    }

    let auth_result = identity_ref.map_or(AuthResult::Anonymous, |id| AuthResult::Authenticated {
        method: id.auth_method(),
    });
    request.extensions_mut().insert(AuthContext::new(
        identity,
        client_ip,
        request_id,
        auth_result,
    ));

    next.run(request).await
}

/// Run the failure path: emit the audit event, fill the logging
/// context, install an `AuthContext` with `AuthResult::Failed`, and
/// convert the `AuthError` into a response. Centralized so the main
/// function reads top-to-bottom without an early-return tangent.
fn handle_auth_failure(
    audit: Option<&dyn AuditLogger>,
    request: &Request,
    request_id: String,
    client_ip: String,
    error: rusty_gasket::auth::error::AuthError,
) -> Response {
    // The full error string can carry attacker-controlled bytes (a JWT
    // `kid`, custom header values). Keep it in the rich audit and
    // `FailedReason` channels where downstream code can decide what to
    // log; use the bounded category label for the analytics field.
    let reason = error.to_string();
    let category = error.category();

    if let Some(logger) = audit {
        let outcome = match &error {
            rusty_gasket::auth::error::AuthError::BackendError(_)
            | rusty_gasket::auth::error::AuthError::Configuration(_) => AuthAuditOutcome::Error {
                error: reason.clone(),
            },
            _ => AuthAuditOutcome::Denied {
                reason: reason.clone(),
            },
        };
        logger.log_auth_event(&AuthAuditEvent {
            request_id: request_id.clone(),
            client_ip: client_ip.clone(),
            auth_method: None,
            subject: None,
            outcome,
        });
    }

    populate_logging_context(
        request,
        AuthSummary::builder()
            .client_ip(client_ip.clone())
            .user_id(Cow::Borrowed("unknown"))
            .auth_method(Cow::Borrowed("unknown"))
            .auth_result(format!("failed:{category}"))
            .build(),
    );

    let ctx = AuthContext::new(
        None,
        client_ip,
        request_id,
        AuthResult::Failed(FailedReason::new(reason)),
    );

    let mut response = error.into_response();
    response.extensions_mut().insert(ctx);
    response
}

/// Emit the success/anonymous audit event, when an audit logger is
/// configured. Failure is handled in [`handle_auth_failure`].
fn audit_success_or_anonymous(
    audit: Option<&dyn AuditLogger>,
    request_id: &str,
    client_ip: &str,
    identity: Option<&Identity>,
) {
    let Some(logger) = audit else { return };
    let event = match identity {
        Some(id) => AuthAuditEvent {
            request_id: request_id.to_owned(),
            client_ip: client_ip.to_owned(),
            auth_method: Some(id.auth_method().to_owned()),
            subject: Some(id.subject().to_owned()),
            outcome: AuthAuditOutcome::Success,
        },
        None => AuthAuditEvent {
            request_id: request_id.to_owned(),
            client_ip: client_ip.to_owned(),
            auth_method: None,
            subject: None,
            outcome: AuthAuditOutcome::Anonymous,
        },
    };
    logger.log_auth_event(&event);
}

/// Build the `AuthSummary` that the observability layer reads back
/// off `LoggingContext` after the response. The shape mirrors the
/// `Authenticated`/`Anonymous` variants of [`AuthResult`]; the failure
/// path uses its own summary in [`handle_auth_failure`].
fn build_success_summary(client_ip: &str, identity: Option<&Identity>) -> AuthSummary {
    match identity {
        Some(id) => {
            let subject = id.subject().to_owned();
            AuthSummary::builder()
                .client_id(subject.clone())
                .client_ip(client_ip.to_owned())
                .user_id(subject)
                .auth_method(Cow::Borrowed(id.auth_method()))
                .auth_result(format!("authenticated:{}", id.auth_method()))
                .privileged(id.is_privileged())
                .build()
        }
        None => AuthSummary::builder()
            .client_ip(Cow::Owned(client_ip.to_owned()))
            .user_id(Cow::Borrowed("anonymous"))
            .auth_method(Cow::Borrowed("none"))
            .auth_result(Cow::Borrowed("anonymous"))
            .build(),
    }
}

/// Fill the `LoggingContext` created by the observability middleware so
/// auth fields appear in the root request tracing span.
fn populate_logging_context(request: &Request, summary: AuthSummary) {
    if let Some(logging_ctx) = request.extensions().get::<LoggingContext>() {
        logging_ctx.set(summary);
    }
}

/// Extract client IP from standard forwarding headers, falling back
/// to the connection's remote address.
///
/// Prefers `X-Real-IP` (typically set by the outermost reverse proxy)
/// over `X-Forwarded-For` (which is trivially spoofable by clients).
/// In production, the infrastructure must ensure only the trusted
/// reverse proxy sets `X-Real-IP`.
fn extract_client_ip(request: &Request) -> String {
    // X-Real-IP is preferred: set by the trusted reverse proxy (nginx, ALB)
    if let Some(real_ip) = request.headers().get("x-real-ip")
        && let Ok(val) = real_ip.to_str()
    {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // X-Forwarded-For: use only as a fallback; the first IP is client-provided
    // and spoofable unless the proxy strips and re-adds it
    if let Some(forwarded) = request.headers().get("x-forwarded-for")
        && let Ok(val) = forwarded.to_str()
        && let Some(first_ip) = val.split(',').next()
    {
        let trimmed = first_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |ci| ci.0.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request as HttpRequest;

    #[test]
    fn extract_ip_from_x_forwarded_for() {
        let req = HttpRequest::builder()
            .header("x-forwarded-for", "10.0.0.1, 192.168.1.1")
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn extract_ip_from_x_forwarded_for_single() {
        let req = HttpRequest::builder()
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "203.0.113.50");
    }

    #[test]
    fn extract_ip_from_x_real_ip() {
        let req = HttpRequest::builder()
            .header("x-real-ip", "10.0.0.2")
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "10.0.0.2");
    }

    #[test]
    fn extract_ip_x_real_ip_takes_priority() {
        let req = HttpRequest::builder()
            .header("x-forwarded-for", "10.0.0.1")
            .header("x-real-ip", "10.0.0.2")
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "10.0.0.2");
    }

    #[test]
    fn extract_ip_empty_forwarded_falls_through() {
        let req = HttpRequest::builder()
            .header("x-forwarded-for", "")
            .header("x-real-ip", "10.0.0.2")
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "10.0.0.2");
    }

    #[test]
    fn extract_ip_no_headers_returns_unknown() {
        let req = HttpRequest::builder()
            .body(Body::empty())
            .expect("valid request");
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "unknown");
    }
}
