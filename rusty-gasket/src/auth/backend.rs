//! Authentication backend trait.
//!
//! Each backend knows how to extract credentials from a request and
//! validate them into an [`Identity`]. Backends are composed via
//! [`AuthChain`](rusty_gasket::auth::AuthChain) and tried in registration order.

use std::future::Future;

use rusty_gasket::BoxFuture;

use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// Extract a bearer token from an `Authorization` header value.
///
/// Returns the token string if the header starts with "Bearer "
/// (case-insensitive per RFC 6750). Returns `None` otherwise.
///
/// The prefix comparison is byte-wise (ASCII-only), so non-UTF-8 boundaries
/// after byte 7 cannot cause a panic — `"Bearer "` is fixed ASCII and any
/// header that starts with those 7 bytes has a valid char boundary at offset 7.
#[must_use]
pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    const PREFIX: &[u8] = b"Bearer ";
    let bytes = header_value.as_bytes();
    let prefix_bytes = bytes.get(..PREFIX.len())?;
    if prefix_bytes.eq_ignore_ascii_case(PREFIX) {
        Some(&header_value[PREFIX.len()..])
    } else {
        None
    }
}

/// Trait that all authentication backends implement.
///
/// Each backend knows how to extract credentials from a request
/// and validate them into an `Identity`.
///
/// # Return values
///
/// - `Ok(Some(identity))` — authentication succeeded
/// - `Ok(None)` — this backend does not apply (e.g., no Bearer header for a JWT backend)
/// - `Err(AuthError)` — a definitive authentication failure (bad token, expired, etc.)
///
/// # Implementing a custom backend
///
/// Backends can be implemented with plain `async fn`; the framework handles
/// dyn-compatible storage inside [`AuthBackendHandle`] and [`AuthChain`](rusty_gasket::auth::AuthChain).
/// The shape is:
///
/// ```no_run
/// use rusty_gasket::auth::{AuthBackend, AuthError, Identity};
///
/// struct StaticHeaderBackend {
///     header: &'static str,
///     expected: &'static str,
///     subject: &'static str,
/// }
///
/// impl AuthBackend for StaticHeaderBackend {
///     fn name(&self) -> &'static str {
///         "static-header"
///     }
///
///     async fn authenticate(
///         &self,
///         headers: &http::HeaderMap,
///         _uri: &http::Uri,
///     ) -> Result<Option<Identity>, AuthError> {
///         let Some(value) = headers.get(self.header).and_then(|v| v.to_str().ok())
///         else {
///             // Header absent; backend doesn't apply, so defer to the next.
///             return Ok(None);
///         };
///         if value == self.expected {
///             Ok(Some(Identity::new(self.subject, "static-header")))
///         } else {
///             Err(AuthError::InvalidCredentials("bad header value".into()))
///         }
///     }
/// }
/// ```
pub trait AuthBackend: Send + Sync + 'static {
    /// Short, stable name for this backend (e.g., "jwt", "api-key").
    /// Used in logs, metrics, and `Identity.auth_method`.
    fn name(&self) -> &'static str;

    /// Attempt to authenticate the request from its headers, cookies, and metadata.
    fn authenticate<'ctx>(
        &'ctx self,
        headers: &'ctx http::HeaderMap,
        uri: &'ctx http::Uri,
    ) -> impl Future<Output = Result<Option<Identity>, AuthError>> + Send + 'ctx;
}

/// Dyn-compatible version of [`AuthBackend`] used inside [`rusty_gasket::auth::AuthChain`].
///
/// Public backends implement [`AuthBackend`] with normal `async fn`. The
/// chain stores mixed backend types together, so this private trait performs
/// the future boxing in one framework-owned place.
trait ErasedAuthBackend: Send + Sync + 'static {
    /// Return the public backend name.
    fn name(&self) -> &'static str;

    /// Forward authentication and return the future in a common stored shape.
    fn authenticate<'ctx>(
        &'ctx self,
        headers: &'ctx http::HeaderMap,
        uri: &'ctx http::Uri,
    ) -> BoxFuture<'ctx, Result<Option<Identity>, AuthError>>;
}

impl<T> ErasedAuthBackend for T
where
    T: AuthBackend,
{
    fn name(&self) -> &'static str {
        AuthBackend::name(self)
    }

    fn authenticate<'ctx>(
        &'ctx self,
        headers: &'ctx http::HeaderMap,
        uri: &'ctx http::Uri,
    ) -> BoxFuture<'ctx, Result<Option<Identity>, AuthError>> {
        // The public trait returns an anonymous future. Boxing it here keeps
        // backend implementations readable while allowing a dynamic chain.
        Box::pin(AuthBackend::authenticate(self, headers, uri))
    }
}

/// An authentication backend handle for dynamic chains.
///
/// Most applications should use [`AuthChain::new`](rusty_gasket::auth::AuthChain::new)
/// and add backend values directly with
/// [`AuthChain::backend`](rusty_gasket::auth::AuthChain::backend). Use
/// `AuthBackendHandle` when assembling backend lists dynamically.
pub struct AuthBackendHandle {
    /// The dyn-compatible backend object used by `AuthChain`.
    inner: Box<dyn ErasedAuthBackend>,
}

impl AuthBackendHandle {
    /// Store an authentication backend behind a readable framework handle.
    pub fn new(backend: impl AuthBackend) -> Self {
        Self {
            inner: Box::new(backend),
        }
    }

    /// Short, stable backend name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// Run this backend against one request.
    pub(crate) fn authenticate<'ctx>(
        &'ctx self,
        headers: &'ctx http::HeaderMap,
        uri: &'ctx http::Uri,
    ) -> BoxFuture<'ctx, Result<Option<Identity>, AuthError>> {
        self.inner.authenticate(headers, uri)
    }
}

impl std::fmt::Debug for AuthBackendHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthBackendHandle")
            .field(&self.name())
            .finish()
    }
}

/// Backward-compatible name for dynamic auth backend storage.
///
/// Prefer [`AuthBackendHandle`] in new framework and application code.
pub type BoxAuthBackend = AuthBackendHandle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
    }

    #[test]
    fn case_insensitive_prefix() {
        assert_eq!(extract_bearer_token("bearer xyz"), Some("xyz"));
        assert_eq!(extract_bearer_token("BEARER xyz"), Some("xyz"));
        assert_eq!(extract_bearer_token("BeArEr xyz"), Some("xyz"));
    }

    #[test]
    fn rejects_non_bearer_scheme() {
        assert_eq!(extract_bearer_token("Basic abc123"), None);
        assert_eq!(extract_bearer_token("Token abc123"), None);
    }

    #[test]
    fn rejects_short_input() {
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("Bear"), None);
        assert_eq!(extract_bearer_token("Bearer"), None);
    }

    #[test]
    fn handles_multibyte_after_prefix() {
        // Multi-byte UTF-8 in the token portion must not panic on slicing.
        assert_eq!(extract_bearer_token("Bearer 日本語"), Some("日本語"));
    }

    #[test]
    fn handles_multibyte_in_prefix_position() {
        // 'é' is 2 bytes (c3 a9), so the byte-level prefix won't match.
        assert_eq!(extract_bearer_token("Béarer x"), None);
    }

    #[test]
    fn empty_token_after_prefix() {
        assert_eq!(extract_bearer_token("Bearer "), Some(""));
    }
}
