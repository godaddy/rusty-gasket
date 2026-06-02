//! Auth backend chain: tries multiple backends in order.
//!
//! The first backend to return `Ok(Some(identity))` wins. If all backends
//! return `Ok(None)`, the [`UnauthenticatedPolicy`] determines whether
//! the request is rejected or allowed through anonymously.

use rusty_gasket::auth::backend::{AuthBackend, AuthBackendHandle};
use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// What to do when no backend produces an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnauthenticatedPolicy {
    /// Reject the request with 401 Unauthorized.
    Reject,

    /// Allow the request through with no identity.
    /// Useful for routes that serve both authenticated and anonymous users.
    AllowAnonymous,
}

/// Composes multiple `AuthBackend` implementations. Tries each backend
/// in registration order; the first one returning `Ok(Some(identity))` wins.
///
/// If all backends return `Ok(None)`, the `fallback` policy determines
/// whether the request is rejected or allowed through anonymously.
pub struct AuthChain {
    backends: Vec<AuthBackendHandle>,
    fallback: UnauthenticatedPolicy,
}

impl std::fmt::Debug for AuthChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthChain")
            .field(
                "backends",
                &self.backends.iter().map(|b| b.name()).collect::<Vec<_>>(),
            )
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl AuthChain {
    /// Create an empty chain with a reject-by-default fallback.
    ///
    /// Add backends with [`Self::backend`]:
    ///
    /// ```no_run
    /// # use rusty_gasket::auth::{AuthChain, JwtBackend};
    /// # fn example(jwt: JwtBackend) {
    /// let chain = AuthChain::new().backend(jwt);
    /// # let _ = chain;
    /// # }
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            fallback: UnauthenticatedPolicy::Reject,
        }
    }

    /// Create a chain from already-created backend handles.
    ///
    /// This is mainly for dynamic plugin-style assembly. Application code
    /// should usually prefer [`Self::new`] plus [`Self::backend`].
    #[must_use]
    pub fn from_backends(backends: Vec<AuthBackendHandle>) -> Self {
        Self::new().backends(backends)
    }

    /// Add one backend to the end of the chain.
    #[must_use]
    pub fn backend(mut self, backend: impl AuthBackend) -> Self {
        self.backends.push(AuthBackendHandle::new(backend));
        self
    }

    /// Add one already-created backend handle to the end of the chain.
    #[must_use]
    pub fn backend_handle(mut self, backend: AuthBackendHandle) -> Self {
        self.backends.push(backend);
        self
    }

    /// Add one already-created backend handle to the end of the chain.
    ///
    /// Prefer [`Self::backend_handle`] in new code.
    #[must_use]
    pub fn boxed_backend(self, backend: AuthBackendHandle) -> Self {
        self.backend_handle(backend)
    }

    /// Add already-created backend handles to the end of the chain.
    #[must_use]
    pub fn backends(mut self, backends: impl IntoIterator<Item = AuthBackendHandle>) -> Self {
        self.backends.extend(backends);
        self
    }

    /// Override the fallback policy for unauthenticated requests.
    #[must_use]
    pub const fn with_fallback(mut self, policy: UnauthenticatedPolicy) -> Self {
        self.fallback = policy;
        self
    }

    /// Run the chain against the given request headers and URI.
    ///
    /// Returns the identity on success, or an error if authentication
    /// fails or no backend matches and the policy is `Reject`.
    ///
    /// Backends are tried in registration order. The chain stops as soon as a
    /// backend reaches a definitive verdict:
    /// - `Ok(Some(identity))` → authenticated; return immediately.
    /// - `Ok(None)` → backend has no opinion (no matching credential header);
    ///   try the next backend.
    /// - `Err(_)` → backend rejected the credential it found (bad signature,
    ///   expired token, transport failure); return immediately, the chain does
    ///   **not** fall through to later backends.
    ///
    /// This means a backend that found a credential it could not validate is
    /// authoritative for that request: an invalid JWT does not silently fall
    /// through to API-key validation. Backends should therefore return
    /// `Ok(None)` when they have nothing to say about a request and reserve
    /// `Err(_)` for credentials they recognized but rejected.
    ///
    /// # Errors
    /// Returns the first error reported by a backend (see semantics above),
    /// or [`AuthError::MissingCredentials`] when no backend produced an
    /// identity and the configured fallback is
    /// [`UnauthenticatedPolicy::Reject`].
    pub async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        for backend in &self.backends {
            match backend.authenticate(headers, uri).await {
                Ok(Some(identity)) => {
                    tracing::debug!(
                        backend = backend.name(),
                        subject = %identity.subject(),
                        "Authentication succeeded"
                    );
                    return Ok(Some(identity));
                }
                Ok(None) => continue,
                Err(e) => {
                    let request_id =
                        rusty_gasket::observability::current_request_id().unwrap_or_default();
                    tracing::warn!(
                        request_id = %request_id,
                        backend = backend.name(),
                        error = %e,
                        "Authentication backend returned error"
                    );
                    return Err(e);
                }
            }
        }

        match self.fallback {
            UnauthenticatedPolicy::AllowAnonymous => Ok(None),
            UnauthenticatedPolicy::Reject => Err(AuthError::MissingCredentials(
                "No valid credentials provided".to_string(),
            )),
        }
    }

    /// Return the current fallback policy for unauthenticated requests.
    #[must_use]
    pub const fn fallback_policy(&self) -> UnauthenticatedPolicy {
        self.fallback
    }
}

impl Default for AuthChain {
    fn default() -> Self {
        Self::new()
    }
}
