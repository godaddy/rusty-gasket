//! Built-in authentication backend implementations.
//!
//! Each backend is gated behind a Cargo feature flag so applications
//! only compile the validation logic they actually use.

/// JWT authentication backend (Bearer token validation).
#[cfg(feature = "auth")]
pub mod jwt;

/// API key authentication backend (header or query parameter).
#[cfg(feature = "auth-api-key")]
pub mod api_key;
