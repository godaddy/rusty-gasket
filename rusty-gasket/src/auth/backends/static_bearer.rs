//! Static shared-secret Bearer token authentication backend.
//!
//! [`StaticBearerBackend`] authenticates a request when its
//! `Authorization: Bearer <token>` header carries one specific,
//! pre-shared secret. It is the simplest possible credential: a single
//! constant token, compared in constant time, that maps to one fixed
//! [`Identity`].
//!
//! This is deliberately *not* a general-purpose user authentication
//! mechanism — there are no claims, no expiry, and no revocation beyond
//! redeploying with a new secret. It exists for the narrow but common
//! case of a machine-to-machine endpoint guarded by a shared token: an
//! internal push/webhook receiver, a health-probe sidecar, or a
//! single-tenant admin hook. Pair it with
//! [`RouteGroup::ProtectedWith`](rusty_gasket::plugin::RouteGroup::ProtectedWith)
//! and [`GasketAppBuilder::auth_chain`](rusty_gasket::plugin::GasketAppBuilder::auth_chain)
//! so that only the endpoints that should accept the shared token sit
//! behind it, while the rest of the service keeps its normal chain.
//!
//! # Security
//!
//! - The expected token is held in a [`secrecy::SecretString`] so it is
//!   not accidentally logged via `Debug` and is zeroized on drop.
//! - The presented token is compared against the secret with the
//!   constant-time primitive from the `subtle` crate, so a caller cannot
//!   recover the secret byte-by-byte through response-timing analysis.

use subtle::ConstantTimeEq as _;

use rusty_gasket::auth::backend::{AuthBackend, extract_bearer_token};
use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// Authentication backend that accepts one pre-shared Bearer token.
///
/// A request authenticates when its `Authorization` header is
/// `Bearer <token>` and `<token>` equals the configured secret. On a
/// match the backend produces a fixed [`Identity`] whose `auth_method`
/// is `"static-bearer"`.
///
/// Construct with [`StaticBearerBackend::new`] and customize the produced
/// identity with the chainable [`subject`](Self::subject),
/// [`service_account`](Self::service_account), and
/// [`privileged`](Self::privileged) builders:
///
/// ```no_run
/// # use rusty_gasket::auth::StaticBearerBackend;
/// let backend = StaticBearerBackend::new("s3cr3t-push-token")
///     .subject("push-webhook")
///     .service_account(true);
/// # let _ = backend;
/// ```
///
/// # Chain semantics
///
/// The backend follows the [`AuthChain`](rusty_gasket::auth::AuthChain)
/// contract: it returns `Ok(None)` (defer to the next backend) when there
/// is no usable Bearer credential to evaluate, and a definitive
/// `Err(AuthError::InvalidCredentials)` when a Bearer token is present but
/// does not match. A non-matching token is therefore *not* silently
/// passed to later backends.
pub struct StaticBearerBackend {
    /// The expected shared secret. Held in `SecretString` so it is not
    /// logged through `Debug` and is zeroized when the backend is dropped.
    token: secrecy::SecretString,
    /// Subject recorded on the produced identity (default
    /// `"static-bearer"`).
    subject: &'static str,
    /// Whether the produced identity is flagged as a service account.
    service_account: bool,
    /// Whether the produced identity is flagged as privileged.
    privileged: bool,
}

impl std::fmt::Debug for StaticBearerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret. `SecretString`'s own `Debug` already
        // redacts, but we also omit it here so the struct output stays
        // obviously secret-free.
        f.debug_struct("StaticBearerBackend")
            .field("subject", &self.subject)
            .field("service_account", &self.service_account)
            .field("privileged", &self.privileged)
            .finish_non_exhaustive()
    }
}

impl StaticBearerBackend {
    /// The default subject recorded on the produced identity.
    const DEFAULT_SUBJECT: &'static str = "static-bearer";

    /// The `auth_method` recorded on every identity this backend produces.
    const AUTH_METHOD: &'static str = "static-bearer";

    /// Create a backend that accepts the given shared secret.
    ///
    /// The produced identity defaults to subject `"static-bearer"`, not a
    /// service account, and not privileged. Use the chainable builders to
    /// change those.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: secrecy::SecretString::from(token.into()),
            subject: Self::DEFAULT_SUBJECT,
            service_account: false,
            privileged: false,
        }
    }

    /// Set the subject recorded on the produced identity.
    #[must_use]
    pub const fn subject(mut self, subject: &'static str) -> Self {
        self.subject = subject;
        self
    }

    /// Flag the produced identity as a service (machine) account.
    ///
    /// See [`Identity::is_service_account`].
    #[must_use]
    pub const fn service_account(mut self, service_account: bool) -> Self {
        self.service_account = service_account;
        self
    }

    /// Flag the produced identity as privileged.
    ///
    /// See [`Identity::is_privileged`].
    #[must_use]
    pub const fn privileged(mut self, privileged: bool) -> Self {
        self.privileged = privileged;
        self
    }

    /// Build the fixed identity produced on a successful match.
    fn identity(&self) -> Identity {
        Identity::builder(self.subject, Self::AUTH_METHOD)
            .service_account(self.service_account)
            .privileged(self.privileged)
            .build()
    }
}

impl AuthBackend for StaticBearerBackend {
    fn name(&self) -> &'static str {
        "static-bearer"
    }

    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        // No Authorization header at all: this backend has no opinion,
        // defer to the next one in the chain.
        let Some(header) = headers.get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };

        // A header that is not valid UTF-8, or that does not use the
        // Bearer scheme, is likewise not ours to judge.
        let Some(token) = header.to_str().ok().and_then(extract_bearer_token) else {
            return Ok(None);
        };

        // Constant-time comparison so the secret cannot be recovered
        // byte-by-byte from response timing. Length differences are not
        // secret, so a fast length check before the constant-time body is
        // acceptable and avoids `ct_eq` on mismatched-length slices.
        use secrecy::ExposeSecret as _;
        let expected = self.token.expose_secret().as_bytes();
        let presented = token.as_bytes();
        let matches = presented.len() == expected.len() && presented.ct_eq(expected).into();

        if matches {
            Ok(Some(self.identity()))
        } else {
            // A Bearer token was presented but did not match: definitive
            // failure, do not fall through to later backends.
            Err(AuthError::InvalidCredentials(
                "static bearer token mismatch".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `Authorization: Bearer <value>` header map.
    fn bearer(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {value}")
                .parse()
                .expect("valid header value"),
        );
        headers
    }

    fn uri() -> http::Uri {
        "/test".parse().expect("valid uri")
    }

    #[tokio::test]
    async fn correct_token_authenticates() {
        let backend = StaticBearerBackend::new("correct-horse");
        let identity = backend
            .authenticate(&bearer("correct-horse"), &uri())
            .await
            .expect("authentication should not error")
            .expect("a matching token yields an identity");

        assert_eq!(identity.subject(), "static-bearer");
        assert_eq!(identity.auth_method(), "static-bearer");
        assert!(!identity.is_service_account());
        assert!(!identity.is_privileged());
    }

    #[tokio::test]
    async fn flags_and_subject_propagate() {
        let backend = StaticBearerBackend::new("token")
            .subject("push-bot")
            .service_account(true)
            .privileged(true);
        let identity = backend
            .authenticate(&bearer("token"), &uri())
            .await
            .expect("authentication should not error")
            .expect("a matching token yields an identity");

        assert_eq!(identity.subject(), "push-bot");
        assert_eq!(identity.auth_method(), "static-bearer");
        assert!(identity.is_service_account());
        assert!(identity.is_privileged());
    }

    #[tokio::test]
    async fn wrong_token_is_invalid_credentials() {
        let backend = StaticBearerBackend::new("correct");
        let err = backend
            .authenticate(&bearer("wrong"), &uri())
            .await
            .expect_err("a non-matching token must be a definitive failure");

        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn missing_authorization_defers() {
        let backend = StaticBearerBackend::new("correct");
        let result = backend
            .authenticate(&http::HeaderMap::new(), &uri())
            .await
            .expect("a missing header must not error");

        assert!(result.is_none(), "no header → defer to next backend");
    }

    #[tokio::test]
    async fn non_bearer_scheme_defers() {
        let backend = StaticBearerBackend::new("correct");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic correct".parse().expect("valid header value"),
        );

        let result = backend
            .authenticate(&headers, &uri())
            .await
            .expect("a non-Bearer scheme must not error");

        assert!(
            result.is_none(),
            "non-Bearer scheme → defer to next backend"
        );
    }

    #[tokio::test]
    async fn empty_presented_token_is_invalid() {
        // `Authorization: Bearer ` (empty token) is a Bearer credential
        // that simply does not match a non-empty secret: definitive error,
        // no panic.
        let backend = StaticBearerBackend::new("correct");
        let err = backend
            .authenticate(&bearer(""), &uri())
            .await
            .expect_err("empty presented token cannot match a non-empty secret");

        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn empty_secret_matches_empty_presented_token() {
        // Degenerate but well-defined: an empty configured secret matches
        // an empty presented token. Documents the constant-time path does
        // not special-case zero length.
        let backend = StaticBearerBackend::new("");
        let identity = backend
            .authenticate(&bearer(""), &uri())
            .await
            .expect("authentication should not error")
            .expect("empty secret matches empty presented token");

        assert_eq!(identity.subject(), "static-bearer");
    }

    #[tokio::test]
    async fn garbage_token_is_invalid_without_panic() {
        let backend = StaticBearerBackend::new("correct");
        let err = backend
            .authenticate(&bearer("!@#$%^&*()_+-=[]{};':\""), &uri())
            .await
            .expect_err("garbage token must be a definitive failure");

        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn non_ascii_header_defers_without_panic() {
        // A header value carrying raw multi-byte UTF-8 is not visible-ASCII,
        // so `HeaderValue::to_str()` fails and the backend has no usable
        // token to evaluate. It must defer (`Ok(None)`) — never panic on a
        // multi-byte boundary. (Token-level multibyte handling of the
        // `extract_bearer_token` helper itself is covered in `backend.rs`.)
        let backend = StaticBearerBackend::new("correct");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_bytes("Bearer 日本語トークン".as_bytes())
                .expect("non-ASCII bytes are a valid header value"),
        );

        let result = backend
            .authenticate(&headers, &uri())
            .await
            .expect("a non-ASCII header must not error");

        assert!(result.is_none(), "non-ASCII header → defer to next backend");
    }

    #[tokio::test]
    async fn long_ascii_secret_matches_itself() {
        // A long ASCII secret round-trips correctly through the
        // constant-time byte comparison (guards against an off-by-one in
        // the length check or `ct_eq`).
        let secret = "x".repeat(512);
        let backend = StaticBearerBackend::new(secret.clone());
        let identity = backend
            .authenticate(&bearer(&secret), &uri())
            .await
            .expect("authentication should not error")
            .expect("a matching long token yields an identity");

        assert_eq!(identity.auth_method(), "static-bearer");
    }

    #[tokio::test]
    async fn prefix_of_secret_is_invalid() {
        // A token that is a strict prefix of the secret must fail (guards
        // against an accidental length-only or prefix comparison).
        let backend = StaticBearerBackend::new("correct-token");
        let err = backend
            .authenticate(&bearer("correct"), &uri())
            .await
            .expect_err("a prefix of the secret must not authenticate");

        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(StaticBearerBackend::new("x").name(), "static-bearer");
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let backend = StaticBearerBackend::new("super-secret-value");
        let rendered = format!("{backend:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "Debug output must not contain the secret: {rendered}"
        );
    }
}
