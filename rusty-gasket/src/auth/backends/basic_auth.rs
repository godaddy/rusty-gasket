//! Static shared-credential HTTP Basic authentication backend.
//!
//! [`BasicAuthBackend`] authenticates a request when its
//! `Authorization: Basic <base64(user:pass)>` header carries one specific,
//! pre-shared username and password. Like [`StaticBearerBackend`] it is a
//! single fixed credential — no user store, no claims, no expiry — but using
//! the HTTP Basic scheme, which browsers prompt for natively. It exists for the
//! common case of a human-facing internal page guarded by one password: an
//! admin/diagnostics view, a staging gate, an internal dashboard. Pair it with
//! [`RouteGroup::ProtectedWith`](rusty_gasket::plugin::RouteGroup::ProtectedWith)
//! and [`GasketAppBuilder::auth_chain`](rusty_gasket::plugin::GasketAppBuilder::auth_chain)
//! so only the protected endpoints sit behind it.
//!
//! [`StaticBearerBackend`]: rusty_gasket::auth::StaticBearerBackend
//!
//! # Security
//!
//! - The expected username and password are held in [`secrecy::SecretString`]
//!   so they are not logged via `Debug` and are zeroized on drop.
//! - Both the presented username and password are compared against the
//!   configured values with the constant-time primitive from the `subtle`
//!   crate, and both comparisons are evaluated before the decision, so a caller
//!   cannot recover either secret byte-by-byte — or learn *which* of the two was
//!   wrong — through response-timing analysis.
//! - Note: this backend validates the credential but does not itself emit a
//!   `WWW-Authenticate: Basic` challenge header on rejection (that is a
//!   response-layer concern); a browser reaching the endpoint without
//!   credentials receives the chain's standard 401.

use base64::Engine as _;
use subtle::ConstantTimeEq as _;

use rusty_gasket::auth::backend::AuthBackend;
use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// Parse an `Authorization: Basic <b64>` value into its `(username, password)`.
///
/// Returns `None` (so the backend defers) when the scheme is not Basic, the
/// payload is not valid base64, the decoded bytes are not UTF-8, or there is no
/// `:` separator. Per RFC 7617 the username cannot contain a `:`, so we split
/// on the first one; the password may contain further colons.
#[must_use]
fn extract_basic_credentials(header_value: &str) -> Option<(String, String)> {
    const PREFIX: &[u8] = b"Basic ";
    let bytes = header_value.as_bytes();
    let prefix_bytes = bytes.get(..PREFIX.len())?;
    if !prefix_bytes.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let encoded = header_value[PREFIX.len()..].trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

/// Authentication backend that accepts one pre-shared HTTP Basic credential.
///
/// A request authenticates when its `Authorization` header is
/// `Basic <base64(username:password)>` and both halves equal the configured
/// secrets. On a match the backend produces a fixed [`Identity`] whose
/// `auth_method` is `"basic-auth"`.
///
/// Construct with [`BasicAuthBackend::new`] and customize the produced identity
/// with the chainable [`subject`](Self::subject),
/// [`service_account`](Self::service_account), and
/// [`privileged`](Self::privileged) builders:
///
/// ```no_run
/// # use rusty_gasket::auth::BasicAuthBackend;
/// let backend = BasicAuthBackend::new("admin", "s3cr3t-diag-password")
///     .subject("diagnostics")
///     .privileged(true);
/// # let _ = backend;
/// ```
///
/// # Chain semantics
///
/// Follows the [`AuthChain`](rusty_gasket::auth::AuthChain) contract: returns
/// `Ok(None)` (defer to the next backend) when there is no usable Basic
/// credential to evaluate, and a definitive `Err(AuthError::InvalidCredentials)`
/// when a Basic credential is present but does not match.
pub struct BasicAuthBackend {
    /// Expected username. Held in `SecretString` so it is not logged and is
    /// zeroized on drop, and compared in constant time.
    username: secrecy::SecretString,
    /// Expected password. Same protections as `username`.
    password: secrecy::SecretString,
    /// Subject recorded on the produced identity (default `"basic-auth"`).
    subject: &'static str,
    /// Whether the produced identity is flagged as a service account.
    service_account: bool,
    /// Whether the produced identity is flagged as privileged.
    privileged: bool,
}

impl std::fmt::Debug for BasicAuthBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the credential.
        f.debug_struct("BasicAuthBackend")
            .field("subject", &self.subject)
            .field("service_account", &self.service_account)
            .field("privileged", &self.privileged)
            .finish_non_exhaustive()
    }
}

impl BasicAuthBackend {
    /// The default subject recorded on the produced identity.
    const DEFAULT_SUBJECT: &'static str = "basic-auth";

    /// The `auth_method` recorded on every identity this backend produces.
    const AUTH_METHOD: &'static str = "basic-auth";

    /// Create a backend that accepts the given username and password.
    ///
    /// The produced identity defaults to subject `"basic-auth"`, not a service
    /// account, and not privileged. Use the chainable builders to change those.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: secrecy::SecretString::from(username.into()),
            password: secrecy::SecretString::from(password.into()),
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
    #[must_use]
    pub const fn service_account(mut self, service_account: bool) -> Self {
        self.service_account = service_account;
        self
    }

    /// Flag the produced identity as privileged.
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

impl AuthBackend for BasicAuthBackend {
    fn name(&self) -> &'static str {
        "basic-auth"
    }

    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        // No Authorization header at all: defer to the next backend.
        let Some(header) = headers.get(http::header::AUTHORIZATION) else {
            return Ok(None);
        };

        // Not valid UTF-8, or not the Basic scheme / not decodable: not ours.
        let Some((username, password)) = header.to_str().ok().and_then(extract_basic_credentials)
        else {
            return Ok(None);
        };

        // Constant-time comparison of both halves. Length differences are not
        // secret, so a fast length check before `ct_eq` is acceptable. Evaluate
        // both before deciding so timing does not reveal which half was wrong.
        use secrecy::ExposeSecret as _;
        let expected_user = self.username.expose_secret().as_bytes();
        let expected_pass = self.password.expose_secret().as_bytes();
        let user_ok = username.len() == expected_user.len()
            && bool::from(username.as_bytes().ct_eq(expected_user));
        let pass_ok = password.len() == expected_pass.len()
            && bool::from(password.as_bytes().ct_eq(expected_pass));

        if user_ok && pass_ok {
            Ok(Some(self.identity()))
        } else {
            Err(AuthError::InvalidCredentials(
                "basic auth credential mismatch".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `Authorization: Basic base64(user:pass)` header map.
    fn basic(username: &str, password: &str) -> http::HeaderMap {
        let raw = format!("{username}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}")
                .parse()
                .expect("valid header value"),
        );
        headers
    }

    fn uri() -> http::Uri {
        "/admin".parse().expect("valid uri")
    }

    #[tokio::test]
    async fn correct_credentials_authenticate() {
        let backend = BasicAuthBackend::new("admin", "hunter2");
        let identity = backend
            .authenticate(&basic("admin", "hunter2"), &uri())
            .await
            .expect("authentication should not error")
            .expect("matching credentials yield an identity");

        assert_eq!(identity.subject(), "basic-auth");
        assert_eq!(identity.auth_method(), "basic-auth");
        assert!(!identity.is_service_account());
        assert!(!identity.is_privileged());
    }

    #[tokio::test]
    async fn flags_and_subject_propagate() {
        let backend = BasicAuthBackend::new("admin", "pw")
            .subject("diagnostics")
            .service_account(true)
            .privileged(true);
        let identity = backend
            .authenticate(&basic("admin", "pw"), &uri())
            .await
            .expect("authentication should not error")
            .expect("matching credentials yield an identity");

        assert_eq!(identity.subject(), "diagnostics");
        assert!(identity.is_service_account());
        assert!(identity.is_privileged());
    }

    #[tokio::test]
    async fn wrong_password_is_invalid_credentials() {
        let backend = BasicAuthBackend::new("admin", "correct");
        let err = backend
            .authenticate(&basic("admin", "wrong"), &uri())
            .await
            .expect_err("a wrong password must be a definitive failure");
        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn wrong_username_is_invalid_credentials() {
        let backend = BasicAuthBackend::new("admin", "pw");
        let err = backend
            .authenticate(&basic("intruder", "pw"), &uri())
            .await
            .expect_err("a wrong username must be a definitive failure");
        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn missing_authorization_defers() {
        let backend = BasicAuthBackend::new("admin", "pw");
        let result = backend
            .authenticate(&http::HeaderMap::new(), &uri())
            .await
            .expect("a missing header must not error");
        assert!(result.is_none(), "no header → defer to next backend");
    }

    #[tokio::test]
    async fn non_basic_scheme_defers() {
        let backend = BasicAuthBackend::new("admin", "pw");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer sometoken".parse().expect("valid header value"),
        );
        let result = backend
            .authenticate(&headers, &uri())
            .await
            .expect("a non-Basic scheme must not error");
        assert!(result.is_none(), "non-Basic scheme → defer to next backend");
    }

    #[tokio::test]
    async fn malformed_base64_defers() {
        let backend = BasicAuthBackend::new("admin", "pw");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic !!!not-base64!!!"
                .parse()
                .expect("valid header value"),
        );
        let result = backend
            .authenticate(&headers, &uri())
            .await
            .expect("malformed base64 must not error");
        assert!(result.is_none(), "undecodable credential → defer");
    }

    #[tokio::test]
    async fn no_colon_separator_defers() {
        // base64("nocolonhere") has no ':' — not a valid Basic credential.
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolonhere");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}")
                .parse()
                .expect("valid header value"),
        );
        let backend = BasicAuthBackend::new("admin", "pw");
        let result = backend
            .authenticate(&headers, &uri())
            .await
            .expect("missing separator must not error");
        assert!(result.is_none(), "no ':' → defer");
    }

    #[tokio::test]
    async fn password_may_contain_colons() {
        // RFC 7617: only the first ':' separates; the password keeps the rest.
        let backend = BasicAuthBackend::new("admin", "a:b:c");
        let identity = backend
            .authenticate(&basic("admin", "a:b:c"), &uri())
            .await
            .expect("authentication should not error")
            .expect("password with colons authenticates");
        assert_eq!(identity.auth_method(), "basic-auth");
    }

    #[tokio::test]
    async fn prefix_of_password_is_invalid() {
        let backend = BasicAuthBackend::new("admin", "correct-password");
        let err = backend
            .authenticate(&basic("admin", "correct"), &uri())
            .await
            .expect_err("a prefix of the password must not authenticate");
        assert!(matches!(err, AuthError::InvalidCredentials(_)));
    }

    #[tokio::test]
    async fn scheme_is_case_insensitive() {
        // RFC 7617 scheme token is case-insensitive ("basic" == "Basic").
        let raw = base64::engine::general_purpose::STANDARD.encode("admin:pw");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("basic {raw}").parse().expect("valid header value"),
        );
        let backend = BasicAuthBackend::new("admin", "pw");
        let identity = backend
            .authenticate(&headers, &uri())
            .await
            .expect("authentication should not error")
            .expect("lowercase scheme authenticates");
        assert_eq!(identity.subject(), "basic-auth");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(BasicAuthBackend::new("u", "p").name(), "basic-auth");
    }

    #[test]
    fn debug_does_not_leak_credentials() {
        let backend = BasicAuthBackend::new("admin-user", "super-secret-pw");
        let rendered = format!("{backend:?}");
        assert!(
            !rendered.contains("super-secret-pw"),
            "Debug leaked password: {rendered}"
        );
        assert!(
            !rendered.contains("admin-user"),
            "Debug leaked username: {rendered}"
        );
    }
}
