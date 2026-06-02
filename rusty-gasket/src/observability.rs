//! Observability: request IDs, structured logging, and tracing.
//!
//! The logging middleware creates a root tracing span per request with
//! empty auth fields. The auth middleware fills them in via the shared
//! [`LoggingContext`] (bidirectional middleware communication pattern).

mod logging;
pub mod request_id;
mod security;

#[cfg(feature = "otlp")]
pub use logging::init_tracing_with_otel;
pub use logging::{
    AuthSummary, AuthSummaryBuilder, LoggingContext, init_tracing, init_tracing_from_env,
    logging_middleware,
};
pub use request_id::{CURRENT_REQUEST_ID, RequestId, X_REQUEST_ID, current_request_id};
pub use security::SecurityJsonFormat;
