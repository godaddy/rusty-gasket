//! Authentication audit logging.
//!
//! Records authentication outcomes (success, denial, error) for security
//! monitoring and compliance. The default [`TracingAuditLogger`] writes
//! structured events via `tracing`; custom implementations can forward
//! events to SIEM systems, audit databases, or compliance pipelines.

use std::sync::Arc;

/// Trait for logging authentication events.
///
/// The default implementation (`TracingAuditLogger`) writes structured
/// log events via `tracing`. Organization-specific overlays can provide
/// custom implementations (e.g., ECS-compliant JSON formatters).
pub trait AuditLogger: Send + Sync + 'static {
    /// Record an authentication event (success, denial, or error).
    fn log_auth_event(&self, event: &AuthAuditEvent);
}

/// Readable handle for an audit logger shared by middleware state.
#[derive(Clone)]
pub struct AuditLoggerHandle {
    /// Shared logger instance used by all cloned middleware state handles.
    inner: Arc<dyn AuditLogger>,
}

impl AuditLoggerHandle {
    /// Store an audit logger behind a readable framework handle.
    #[must_use]
    pub fn new(logger: impl AuditLogger) -> Self {
        Self {
            inner: Arc::new(logger),
        }
    }

    /// Store an already-shared audit logger.
    #[must_use]
    pub fn shared(logger: Arc<dyn AuditLogger>) -> Self {
        Self { inner: logger }
    }

    /// Borrow the logger for event emission.
    #[must_use]
    pub fn logger(&self) -> &dyn AuditLogger {
        self.inner.as_ref()
    }
}

impl std::fmt::Debug for AuditLoggerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLoggerHandle").finish_non_exhaustive()
    }
}

/// Converts common logger inputs into an [`AuditLoggerHandle`].
pub trait IntoAuditLoggerHandle {
    /// Convert into an audit logger handle.
    fn into_audit_logger_handle(self) -> AuditLoggerHandle;
}

impl<T> IntoAuditLoggerHandle for T
where
    T: AuditLogger,
{
    fn into_audit_logger_handle(self) -> AuditLoggerHandle {
        // Concrete logger values are wrapped here so application builders can
        // pass `TracingAuditLogger` instead of writing `Arc<dyn AuditLogger>`.
        AuditLoggerHandle::new(self)
    }
}

impl<T> IntoAuditLoggerHandle for Arc<T>
where
    T: AuditLogger,
{
    fn into_audit_logger_handle(self) -> AuditLoggerHandle {
        // Preserve caller-provided shared ownership when the logger is already
        // in an `Arc`, avoiding an unnecessary extra allocation layer.
        let inner: Arc<dyn AuditLogger> = self;
        AuditLoggerHandle::shared(inner)
    }
}

impl IntoAuditLoggerHandle for Arc<dyn AuditLogger> {
    fn into_audit_logger_handle(self) -> AuditLoggerHandle {
        // Accept the fully-erased form as an advanced escape hatch while the
        // rest of the API continues to show the named handle type.
        AuditLoggerHandle::shared(self)
    }
}

/// An authentication event to be recorded by the audit logger.
///
/// Construct via [`AuthAuditEvent::new`]; fields can be set with the
/// `with_*` builder methods. Marked `#[non_exhaustive]` so future fields
/// (e.g., timestamp, geo, request method) can be added without breaking
/// downstream `AuditLogger` implementations that read fields by name.
/// Fields are private; read via accessor methods so the event is
/// immutable post-construction (no `&mut AuthAuditEvent` can rewrite
/// the `subject` an audit logger is about to record).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthAuditEvent {
    pub(crate) request_id: String,
    pub(crate) client_ip: String,
    pub(crate) auth_method: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) outcome: AuthAuditOutcome,
}

impl AuthAuditEvent {
    /// Create a new audit event with the given correlation ID, client IP,
    /// and outcome. Optional fields default to `None`.
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        client_ip: impl Into<String>,
        outcome: AuthAuditOutcome,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            client_ip: client_ip.into(),
            auth_method: None,
            subject: None,
            outcome,
        }
    }

    /// Set the auth method (backend name) that handled the request.
    #[must_use]
    pub fn with_auth_method(mut self, method: impl Into<String>) -> Self {
        self.auth_method = Some(method.into());
        self
    }

    /// Set the subject identifier of the authenticated caller.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Correlation ID for the request that triggered this event.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    /// Client IP address extracted from the request.
    #[must_use]
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }
    /// Name of the auth backend that handled the request, if any.
    #[must_use]
    pub fn auth_method(&self) -> Option<&str> {
        self.auth_method.as_deref()
    }
    /// Subject identifier of the authenticated caller, if any.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
    /// Outcome of the authentication attempt.
    #[must_use]
    pub const fn outcome(&self) -> &AuthAuditOutcome {
        &self.outcome
    }
}

/// Outcome of an authentication attempt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthAuditOutcome {
    /// Authentication succeeded and an identity was produced.
    Success,
    /// No credentials provided and anonymous access was allowed.
    Anonymous,
    /// Authentication was attempted but explicitly denied.
    Denied {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// An internal error occurred during authentication.
    Error {
        /// The error message from the backend.
        error: String,
    },
}

/// Default audit logger that writes events via `tracing`.
#[derive(Debug, Default)]
pub struct TracingAuditLogger;

impl AuditLogger for TracingAuditLogger {
    fn log_auth_event(&self, event: &AuthAuditEvent) {
        match &event.outcome {
            AuthAuditOutcome::Success => {
                tracing::info!(
                    request_id = %event.request_id,
                    client_ip = %event.client_ip,
                    auth_method = ?event.auth_method,
                    subject = ?event.subject,
                    "auth.success"
                );
            }
            AuthAuditOutcome::Anonymous => {
                tracing::debug!(
                    request_id = %event.request_id,
                    client_ip = %event.client_ip,
                    "auth.anonymous"
                );
            }
            AuthAuditOutcome::Denied { reason } => {
                tracing::warn!(
                    request_id = %event.request_id,
                    client_ip = %event.client_ip,
                    auth_method = ?event.auth_method,
                    subject = ?event.subject,
                    reason = %reason,
                    "auth.denied"
                );
            }
            AuthAuditOutcome::Error { error } => {
                tracing::error!(
                    request_id = %event.request_id,
                    client_ip = %event.client_ip,
                    error = %error,
                    "auth.error"
                );
            }
        }
    }
}
