//! Per-request database transaction middleware.
//!
//! Begins a tracked transaction for each request (with request ID
//! correlation for database query log tracing) and stores it in
//! request extensions for the [`DbTx`](rusty_gasket::db::DbTx) extractor.

use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::{Any, AnyPool, Transaction};

use rusty_gasket::db::config::ResolvedBackend;

/// Sanitize a request ID for use in database session correlation values.
///
/// Filters to ASCII alphanumerics and dashes (everything else is stripped),
/// then truncates to 55 characters. Combined with the `gasket|` prefix
/// (7 bytes), the resulting value fits `PostgreSQL`'s 64-byte
/// `application_name` column.
pub fn sanitize_request_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(55)
        .collect()
}

/// Begin a transaction with request ID correlation for query log tracing.
///
/// The correlation value is `gasket|<sanitized-request-id>` so operators
/// can grep query logs for the `gasket|` prefix to isolate framework
/// traffic from other writers. The mechanism is database-specific:
/// - **`PostgreSQL`**: `SELECT set_config('application_name', $1, true)` —
///   the prefixed string appears in `pg_stat_activity.application_name`
///   and any `log_line_prefix` that includes `%a`.
/// - **`MySQL`**: `SET @gasket_request_id = ?` — the prefixed string is
///   readable as a session variable, e.g. `SELECT @gasket_request_id`,
///   and surfaces in slow query logs configured to capture session
///   variables. The `gasket|` prefix is included verbatim in the value.
///
/// The request ID is sanitized to ASCII alphanumerics and dashes and
/// truncated to 55 characters before the prefix is applied; the
/// `PostgreSQL` `application_name` column is 64 bytes including the
/// `gasket|` prefix.
///
/// # Errors
/// Returns the underlying `SQLx` error if the transaction cannot be started or
/// the correlation statement fails.
pub async fn begin_tracked_transaction(
    pool: &AnyPool,
    request_id: &str,
    backend: ResolvedBackend,
) -> Result<Transaction<'static, Any>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let sanitized = sanitize_request_id(request_id);
    let app_name = format!("gasket|{sanitized}");

    match backend {
        ResolvedBackend::Postgres => {
            sqlx::query("SELECT set_config('application_name', $1, true)")
                .bind(&app_name)
                .execute(&mut *tx)
                .await?;
        }
        ResolvedBackend::MySql => {
            sqlx::query("SET @gasket_request_id = ?")
                .bind(&app_name)
                .execute(&mut *tx)
                .await?;
        }
    }

    Ok(tx)
}

/// Shared state for the transaction middleware.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TransactionMiddlewareState {
    /// The database connection pool to begin transactions from.
    pub pool: AnyPool,
    /// The resolved backend, used to select the correlation mechanism (`PostgreSQL` vs `MySQL`).
    pub backend: ResolvedBackend,
}

impl TransactionMiddlewareState {
    /// Create middleware state from a connection pool and resolved backend.
    #[must_use]
    pub const fn new(pool: AnyPool, backend: ResolvedBackend) -> Self {
        Self { pool, backend }
    }
}

/// Per-request transaction stored in request extensions.
///
/// Wrapped in `Arc<Mutex>` because `http::Extensions` requires `Clone`,
/// but `Transaction` is not `Clone`. The `DbTx` extractor takes ownership
/// by calling `take()` on the inner `Option`.
#[derive(Debug, Clone)]
pub struct RequestTransaction {
    inner: Arc<Mutex<Option<Transaction<'static, Any>>>>,
}

impl RequestTransaction {
    /// Wrap a transaction for storage in request extensions.
    #[must_use]
    pub fn new(tx: Transaction<'static, Any>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(tx))),
        }
    }

    /// Take the transaction out. Returns `None` if already taken or if the
    /// internal mutex was poisoned by a panic in another task that held it.
    ///
    /// A poisoned mutex is logged at error level so operators can see that a
    /// transaction was orphaned — the lock-poisoning case is otherwise
    /// indistinguishable from a normal "already taken" return.
    #[must_use]
    pub fn take(&self) -> Option<Transaction<'static, Any>> {
        match self.inner.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => {
                tracing::error!(
                    "RequestTransaction mutex poisoned; transaction handle is unrecoverable"
                );
                None
            }
        }
    }
}

/// Axum middleware that begins a tracked database transaction for each
/// request and makes it available via the `DbTx` extractor.
///
/// This middleware is **opt-in per route group**. Apply it only to routes
/// that need a database transaction — read-only endpoints or routes that
/// don't access the database should not use this middleware to avoid
/// wasting connections. Use the `Transaction` middleware slot (after auth,
/// after rate limiting) so that rejected requests don't consume DB connections.
//
// No #[tracing::instrument] here: the root `http_request` span already
// covers the request, and the failure path emits its own structured
// event with request_id. A second per-request span just adds allocation.
pub async fn transaction_middleware(
    State(state): State<Arc<TransactionMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<rusty_gasket::observability::RequestId>()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();

    match begin_tracked_transaction(&state.pool, &request_id, state.backend).await {
        Ok(tx) => {
            request.extensions_mut().insert(RequestTransaction::new(tx));
            next.run(request).await
        }
        Err(e) => {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "Failed to begin database transaction"
            );
            rusty_gasket::error::quick_error_response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_ERROR",
                "Service temporarily unavailable",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_request_id;

    #[test]
    fn sanitize_normal_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(sanitize_request_id(id), id);
    }

    #[test]
    fn sanitize_strips_special_chars() {
        let id = "req-123; DROP TABLE users;--";
        assert_eq!(sanitize_request_id(id), "req-123DROPTABLEusers--");
    }

    #[test]
    fn sanitize_truncates_long_ids() {
        let id = "a".repeat(100);
        let sanitized = sanitize_request_id(&id);
        assert_eq!(sanitized.len(), 55);
    }

    #[test]
    fn sanitize_empty_id() {
        assert_eq!(sanitize_request_id(""), "");
    }

    #[test]
    fn sanitize_unicode_strips_non_ascii() {
        // is_ascii_alphanumeric() rejects non-ASCII characters, so the
        // Japanese chars are filtered out and only the ASCII parts remain.
        let id = "req-\u{65e5}\u{672c}\u{8a9e}-123";
        assert_eq!(sanitize_request_id(id), "req--123");
    }

    #[test]
    fn sanitize_only_special_chars() {
        assert!(sanitize_request_id("!@#$%^&*()").is_empty());
    }
}
