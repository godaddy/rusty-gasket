//! Axum extractor for `DynamoDB` client access in handlers.
//!
//! Unlike the SQL `DbTx` extractor (in `rusty-gasket-db`), this does not
//! create a per-request transaction. `DynamoDB` transactions are explicit,
//! item-level operations invoked directly on the client.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Axum extractor that provides a `DynamoDB` client to handlers.
///
/// The client is inserted into request extensions by `DynamoPlugin`
/// during prepare (stored as shared state). Unlike the SQL `DbTx`
/// extractor, this does not create a per-request transaction — `DynamoDB`
/// transactions are explicit, item-level operations invoked via the
/// client's `transact_write_items()` / `transact_get_items()` methods.
///
/// # Example
///
/// ```ignore
/// use rusty_gasket::dynamodb::DynamoClient;
///
/// async fn get_item(dynamo: DynamoClient, Path(id): Path<String>) -> impl IntoResponse {
///     let result = dynamo
///         .get_item()
///         .table_name("items")
///         .key("id", AttributeValue::S(id))
///         .send()
///         .await;
///     // ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DynamoClient(pub aws_sdk_dynamodb::Client);

impl std::ops::Deref for DynamoClient {
    type Target = aws_sdk_dynamodb::Client;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error returned when `DynamoClient` extractor fails.
#[derive(Debug)]
pub struct DynamoClientNotAvailable;

impl IntoResponse for DynamoClientNotAvailable {
    fn into_response(self) -> Response {
        rusty_gasket::error::quick_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DYNAMODB_NOT_AVAILABLE",
            "DynamoDB client not available — is DynamoPlugin registered?",
        )
    }
}

impl<S> FromRequestParts<S> for DynamoClient
where
    S: Send + Sync,
{
    type Rejection = DynamoClientNotAvailable;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Try the Extension layer first (set by DynamoPlugin's middleware),
        // then fall back to direct request extensions for backwards compatibility.
        parts
            .extensions
            .get::<axum::Extension<Self>>()
            .map(|ext| ext.0.clone())
            .or_else(|| parts.extensions.get::<Self>().cloned())
            .ok_or(DynamoClientNotAvailable)
    }
}
