//! `DynamoDB` integration for Rusty Gasket.
//!
//! Provides a lifecycle plugin and axum extractor for `DynamoDB` access.
//! This is intentionally separate from `rusty-gasket-db` (SQL) because
//! `DynamoDB`'s key-value/document model is fundamentally different from
//! relational databases — forcing them behind a shared abstraction would
//! produce a lowest-common-denominator API worse than using either directly.
//!
//! # Examples
//!
//! ```ignore
//! use rusty_gasket::dynamodb::{DynamoPlugin, DynamoClient};
//!
//! // Register the plugin
//! let app = GasketApp::builder()
//!     .plugin(DynamoPlugin::default())
//!     .build().await?;
//!
//! // Use in handlers
//! async fn list_items(dynamo: DynamoClient) -> impl IntoResponse {
//!     let result = dynamo.scan().table_name("items").send().await?;
//!     // ...
//! }
//! ```

mod config;
mod extractor;
mod plugin;

pub use config::DynamoConfig;
pub use extractor::DynamoClient;
pub use plugin::DynamoPlugin;
pub use rusty_gasket::BoxError;

/// Re-export the SDK client type for consumers who need direct access.
/// Pinned to the AWS SDK major version this crate was compiled against —
/// bumping `aws-sdk-dynamodb` is a semver-major change for this crate.
pub use aws_sdk_dynamodb::Client as AwsDynamoClient;

/// Re-exports of the most commonly used `DynamoDB` types.
///
/// `use rusty_gasket::dynamodb::prelude::*` to get config, extractor,
/// and plugin in one import.
pub mod prelude {
    pub use rusty_gasket::dynamodb::{BoxError, DynamoClient, DynamoConfig, DynamoPlugin};
}
