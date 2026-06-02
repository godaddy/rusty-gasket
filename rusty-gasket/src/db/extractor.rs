//! Axum extractor for per-request database transactions.
//!
//! [`DbTx`] takes ownership of the transaction begun by
//! `transaction_middleware`. The caller is responsible for committing;
//! if the extractor is dropped without committing, the transaction
//! is automatically rolled back by `SQLx`.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::{Any, Transaction};

use rusty_gasket::db::transaction::RequestTransaction;

/// Axum extractor that takes ownership of the per-request database transaction.
///
/// Works with both `PostgreSQL` and `MySQL` backends via `SQLx`'s `Any` driver.
/// The transaction is begun by `transaction_middleware` and stored in
/// request extensions. This extractor takes it out — only one handler
/// (or extractor) can claim it per request.
///
/// The caller is responsible for committing. If `DbTx` is dropped
/// without committing, the transaction is automatically rolled back.
///
/// # Example
///
/// ```ignore
/// async fn create_entity(mut tx: DbTx) -> impl IntoResponse {
///     sqlx::query("INSERT INTO entities ...").execute(&mut *tx).await?;
///     tx.commit().await?;
///     StatusCode::CREATED
/// }
/// ```
pub struct DbTx(pub Transaction<'static, Any>);

impl std::fmt::Debug for DbTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbTx").finish_non_exhaustive()
    }
}

impl std::ops::Deref for DbTx {
    type Target = Transaction<'static, Any>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for DbTx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DbTx {
    /// Commit the transaction.
    ///
    /// # Errors
    /// Returns the underlying `SQLx` error if the database rejects the commit
    /// (constraint violation, lost connection, etc.).
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.0.commit().await
    }
}

/// Error returned when `DbTx` extractor fails.
#[derive(Debug)]
pub struct DbTxNotAvailable;

impl IntoResponse for DbTxNotAvailable {
    fn into_response(self) -> Response {
        rusty_gasket::error::quick_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_TRANSACTION_NOT_AVAILABLE",
            "Database transaction not available for this request",
        )
    }
}

impl<S> FromRequestParts<S> for DbTx
where
    S: Send + Sync,
{
    type Rejection = DbTxNotAvailable;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let req_tx = parts
            .extensions
            .get::<RequestTransaction>()
            .ok_or(DbTxNotAvailable)?;

        let tx = req_tx.take().ok_or(DbTxNotAvailable)?;
        Ok(Self(tx))
    }
}
