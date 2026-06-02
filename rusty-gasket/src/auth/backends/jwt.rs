//! JWT authentication backend.
//!
//! Validates JSON Web Tokens using the `jsonwebtoken` crate. Supports
//! static keys (HMAC, RSA PEM, EC PEM) and remote JWKS endpoints for
//! automatic key discovery and rotation. Token sources are configurable
//! (Bearer header, cookie, or custom header) and claims mapping is
//! pluggable via the [`ClaimsMapper`](rusty_gasket::auth::backends::jwt::ClaimsMapper) trait.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use tokio::sync::Semaphore;

use rusty_gasket::auth::backend::AuthBackend;
use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// Typed error variants for the JWKS fetch path.
///
/// Surfaces via [`AuthError::BackendError`]'s `Box<dyn Error>`; observability
/// code that wants to distinguish, say, a 503 from a body-too-large should
/// downcast the inner error to this enum rather than parsing the message
/// string.
///
/// ```ignore
/// match auth_err {
///     AuthError::BackendError(b) => match b.downcast_ref::<JwksError>() {
///         Some(JwksError::HttpStatus { status }) => /* alert on 5xx */,
///         Some(JwksError::BodyTooLarge { .. })   => /* alert on bad JWKS */,
///         _ => /* unrelated backend error */,
///     },
///     _ => {}
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// JWKS endpoint returned a non-success HTTP status.
    #[error("JWKS endpoint returned HTTP {status}")]
    HttpStatus {
        /// The non-2xx status code returned by the endpoint.
        status: http::StatusCode,
    },
    /// JWKS response body exceeded the configured cap before EOF.
    #[error("JWKS response exceeds maximum body size of {max_bytes} bytes")]
    BodyTooLarge {
        /// The configured cap, in bytes.
        max_bytes: usize,
    },
    /// The single-flight fetch task panicked or was cancelled by the runtime.
    #[error("JWKS fetch task did not complete: {0}")]
    FetchTask(#[source] tokio::task::JoinError),
}

/// Default cache TTL for JWKS keys.
const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
/// Default HTTP timeout for JWKS endpoint requests.
const DEFAULT_JWKS_TIMEOUT: Duration = Duration::from_secs(10);
/// Default maximum response body size for JWKS endpoints.
///
/// JWKS documents are typically a few KB; we cap at 1 MiB to bound memory.
const DEFAULT_JWKS_MAX_BODY_SIZE: usize = 1 << 20;

/// Where to look for the JWT in the request.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum TokenSource {
    /// `Authorization: Bearer <token>` header (most common).
    #[default]
    BearerHeader,
    /// Named cookie.
    ///
    /// # Security
    ///
    /// Cookie-based JWTs are vulnerable to CSRF unless the browser
    /// refuses to attach the cookie to cross-site requests. Issue the
    /// cookie with `SameSite=Strict` (or `SameSite=Lax` only for GETs
    /// that have no side effects) and supplement with a CSRF token for
    /// any state-changing endpoint. The framework does not bundle CSRF
    /// protection — operators are responsible for it when this token
    /// source is selected.
    ///
    /// If the same cookie name appears more than once in a single
    /// request, the extractor returns `None` so the backend reports
    /// `MissingCredentials` rather than picking a value at random and
    /// enabling cookie-shadowing attacks.
    Cookie(String),
    /// Custom header name. The whole header value is used as the token
    /// after a defensive case-insensitive `Bearer ` strip, so callers
    /// pointing at e.g. an `X-Auth-Token` header that may or may not
    /// carry a `Bearer ` prefix do not have to special-case it.
    Header(String),
}

/// Maps raw JWT claims (as a JSON value) to an `Identity`.
///
/// The default implementation uses standard claims:
/// - `sub` → `Identity.subject`
/// - `scope` (space-separated string) → `Identity.scopes`
/// - `name` → `Identity.display_name`
///
/// Organization-specific overlays can override this to handle custom claim structures.
pub trait ClaimsMapper: Send + Sync + 'static {
    /// Map raw JWT claims (as a JSON value) to an [`Identity`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenValidation`] if required claims are missing
    /// or have unexpected types.
    fn map_claims(&self, claims: &serde_json::Value) -> Result<Identity, AuthError>;
}

/// Readable handle for a JWT claims mapper.
pub struct ClaimsMapperHandle {
    /// The mapper implementation used to translate validated JWT claims.
    mapper: Box<dyn ClaimsMapper>,
}

impl ClaimsMapperHandle {
    /// Store a claims mapper behind a readable framework handle.
    #[must_use]
    pub fn new(mapper: impl ClaimsMapper) -> Self {
        Self {
            mapper: Box::new(mapper),
        }
    }

    /// Map validated JWT claims into the framework identity model.
    fn map_claims(&self, claims: &serde_json::Value) -> Result<Identity, AuthError> {
        self.mapper.map_claims(claims)
    }
}

impl std::fmt::Debug for ClaimsMapperHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimsMapperHandle").finish_non_exhaustive()
    }
}

/// Default claims mapper using standard JWT claims (sub, scope, name).
#[derive(Debug, Default)]
pub struct StandardClaimsMapper;

impl ClaimsMapper for StandardClaimsMapper {
    fn map_claims(&self, claims: &serde_json::Value) -> Result<Identity, AuthError> {
        map_standard_claims(claims, "jwt", None)
    }
}

/// How [`OAuthClaimsMapper`] handles the OAuth `client_id` claim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientIdClaim {
    /// Ignore `client_id` and produce the same identity shape as
    /// [`StandardClaimsMapper`].
    Ignore,
    /// Preserve `client_id` as typed identity metadata.
    #[default]
    Preserve,
}

/// OAuth-specific claims preserved from a JWT access token.
///
/// JWT itself only defines a small set of registered claims. OAuth access
/// tokens commonly include `client_id` to identify the client application
/// that received the token. This typed attribute lets policy wrappers read
/// that value without re-parsing raw JSON claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OAuthTokenClaims {
    client_id: Option<String>,
}

impl OAuthTokenClaims {
    /// Create preserved OAuth claims from an optional client identifier.
    #[must_use]
    pub fn new(client_id: Option<String>) -> Self {
        Self { client_id }
    }

    /// OAuth client identifier, when the token included one.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
}

/// Claims mapper for OAuth-style JWT access tokens.
///
/// It uses the same readable claim mapping as [`StandardClaimsMapper`]:
/// `sub` becomes the identity subject, `scope` becomes identity scopes,
/// and `name` becomes the display name. The difference is that this mapper
/// can also preserve OAuth metadata such as `client_id` as a typed identity
/// attribute for policy wrappers.
#[derive(Debug, Clone, Copy)]
pub struct OAuthClaimsMapper {
    auth_method: &'static str,
    client_id: ClientIdClaim,
}

impl Default for OAuthClaimsMapper {
    fn default() -> Self {
        Self {
            auth_method: "oauth-jwt",
            client_id: ClientIdClaim::Preserve,
        }
    }
}

impl OAuthClaimsMapper {
    /// Create an OAuth claims mapper.
    ///
    /// By default, this preserves `client_id` because OAuth policy layers
    /// commonly need it for service-to-service authorization decisions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a different auth method label in the produced identity.
    #[must_use]
    pub const fn auth_method(mut self, auth_method: &'static str) -> Self {
        self.auth_method = auth_method;
        self
    }

    /// Preserve `client_id` as [`OAuthTokenClaims`] identity metadata.
    #[must_use]
    pub const fn preserve_client_id(mut self) -> Self {
        self.client_id = ClientIdClaim::Preserve;
        self
    }

    /// Ignore `client_id` and avoid adding OAuth-specific identity metadata.
    #[must_use]
    pub const fn ignore_client_id(mut self) -> Self {
        self.client_id = ClientIdClaim::Ignore;
        self
    }

    /// Set the `client_id` handling policy directly.
    ///
    /// The named enum keeps call sites readable and avoids ambiguous
    /// boolean parameters for an auth-relevant decision.
    #[must_use]
    pub const fn client_id_claim(mut self, client_id: ClientIdClaim) -> Self {
        self.client_id = client_id;
        self
    }
}

impl ClaimsMapper for OAuthClaimsMapper {
    fn map_claims(&self, claims: &serde_json::Value) -> Result<Identity, AuthError> {
        let client_id = match self.client_id {
            ClientIdClaim::Ignore => None,
            ClientIdClaim::Preserve => claims
                .get("client_id")
                .and_then(|claim| claim.as_str())
                .map(String::from),
        };

        let oauth_claims =
            (self.client_id == ClientIdClaim::Preserve).then(|| OAuthTokenClaims::new(client_id));
        map_standard_claims(claims, self.auth_method, oauth_claims)
    }
}

/// Build an identity from the common JWT claim shape.
fn map_standard_claims(
    claims: &serde_json::Value,
    auth_method: &'static str,
    oauth_claims: Option<OAuthTokenClaims>,
) -> Result<Identity, AuthError> {
    let subject = claims["sub"]
        .as_str()
        .ok_or_else(|| AuthError::TokenValidation("Missing 'sub' claim".to_string()))?
        .to_string();

    let scopes = scope_claims(claims);
    let display_name = claims
        .get("name")
        .and_then(|claim| claim.as_str())
        .map(String::from);

    let mut builder = Identity::builder(subject, auth_method).scopes(scopes);
    if let Some(name) = display_name {
        builder = builder.display_name(name);
    }
    if let Some(claims) = oauth_claims {
        builder = builder.attribute(claims);
    }
    Ok(builder.build())
}

/// Parse a standard OAuth `scope` string into an identity scope set.
fn scope_claims(claims: &serde_json::Value) -> HashSet<String> {
    claims
        .get("scope")
        .and_then(|claim| claim.as_str())
        .map(|scope| scope.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

/// How the JWT backend resolves decoding keys at validation time.
enum KeyResolver {
    /// A single pre-built key (HMAC, RSA PEM, or EC PEM).
    Static(Box<StaticKey>),
    /// Keys fetched from a remote JWKS endpoint, cached and rotated.
    Jwks(Arc<JwksKeyStore>),
}

struct StaticKey {
    key: DecodingKey,
    validation: Validation,
}

/// Cached JWKS key store with automatic refresh.
///
/// Reads are wait-free: the hot path loads `cached` via `ArcSwap`,
/// looks the `kid` up in a prebuilt `HashMap`, and returns an `Arc`
/// to a `(DecodingKey, Algorithm)` pair that was constructed once at
/// fetch time. There is no per-request lock acquisition, no per-
/// request `Jwk` clone, and no per-request `DecodingKey::from_jwk`
/// reparse.
///
/// Writes go through `fetch_lock` for single-flight semantics so
/// concurrent refresh attempts collapse into a single HTTP round trip.
struct JwksKeyStore {
    url: String,
    cache_ttl: Duration,
    /// Atomic-swap pointer to the current prepared JWKS snapshot.
    /// `None` until the first fetch completes.
    cached: ArcSwapOption<PreparedJwks>,
    /// `Semaphore::new(1)` instead of `Mutex<()>`: we never need to
    /// guard data, just permit one fetcher at a time, and `Semaphore`
    /// expresses that intent more clearly than a unit-payload mutex.
    fetch_lock: Semaphore,
    http_client: reqwest::Client,
    max_body_size: usize,
    allowed_algorithms: Vec<Algorithm>,
    audience: Option<String>,
    issuer: Option<String>,
    validate_exp: bool,
    validate_nbf: bool,
    leeway_secs: u64,
    /// Set of `(kid, reason)` pairs we've already warn-logged about a
    /// drop in `prepare_jwks`. Without this, a JWKS document that
    /// publishes one persistently-broken key would warn on every cache
    /// refresh (every `cache_ttl`, default 5 minutes) forever. Operators
    /// see the warning once; the broken key is then silently filtered
    /// on every subsequent refresh.
    warned_drops: StdMutex<HashSet<String>>,
}

/// A snapshot of the JWKS document with each key pre-converted into a
/// `DecodingKey`. Constructed at fetch time so the validation hot path
/// just needs a hash lookup.
struct PreparedJwks {
    fetched_at: Instant,
    keys: HashMap<String, Arc<PreparedKey>>,
}

struct PreparedKey {
    key: DecodingKey,
    algorithm: Algorithm,
}

/// Outcome of looking up a `kid` in the current cache snapshot.
///
/// `FreshButMissing` is distinguished from `Stale` so that a request
/// presenting an unknown `kid` against a fresh cache does not trigger
/// a refetch — without this distinction, an attacker who sends tokens
/// with random `kid` values could force one JWKS network round trip
/// per token.
enum CacheLookup {
    Hit(Arc<PreparedKey>),
    FreshButMissing,
    Stale,
}

fn kid_not_found(kid: &str) -> AuthError {
    AuthError::TokenValidation(format!("Key '{}' not found in JWKS", sanitize_for_log(kid)))
}

/// Strip ASCII control bytes (including CR/LF) and truncate untrusted
/// strings before embedding them into error messages or log lines.
///
/// Without this, an attacker who controls the `kid` claim of a JWT header
/// (or a custom-header value) can inject newlines and forge fake log
/// entries when the resulting `AuthError` is rendered through a non-JSON
/// tracing formatter.
fn sanitize_for_log(s: &str) -> String {
    const MAX: usize = 128;
    s.chars().filter(|c| !c.is_control()).take(MAX).collect()
}

/// Strip a leading case-insensitive `Bearer ` (or `bearer `) prefix from
/// a header value, returning the remainder. Used by the custom-header
/// token source so callers don't have to special-case the prefix.
fn strip_bearer_prefix(s: &str) -> &str {
    let trimmed = s.trim_start();
    if trimmed.len() >= 7
        && trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"bearer")
        && matches!(trimmed.as_bytes()[6], b' ' | b'\t')
    {
        trimmed[7..].trim_start()
    } else {
        trimmed
    }
}

impl JwksKeyStore {
    async fn resolve_key(
        self: &Arc<Self>,
        token: &str,
    ) -> Result<(DecodingKey, Validation), AuthError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthError::TokenValidation(format!("Invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AuthError::TokenValidation("JWT missing 'kid' header".to_string()))?;

        if !self.allowed_algorithms.contains(&header.alg) {
            // header.alg comes from the token header (attacker-influenced
            // shape); Debug renders the enum variant name only, which is
            // safe.
            return Err(AuthError::TokenValidation(format!(
                "Algorithm {:?} is not in the JWKS allow-list",
                header.alg
            )));
        }

        let prepared = self.find_key(kid).await?;

        // Confusion-deputy check: the cached key was prepared from the JWK
        // that ships its own algorithm. If a token claims a different alg
        // than the JWK is for (e.g. HMAC over an RSA public key), reject.
        if prepared.algorithm != header.alg {
            return Err(AuthError::TokenValidation(format!(
                "JWT alg {:?} does not match JWKS key alg {:?}",
                header.alg, prepared.algorithm
            )));
        }

        let mut validation = Validation::new(prepared.algorithm);
        validation.validate_exp = self.validate_exp;
        validation.validate_nbf = self.validate_nbf;
        validation.leeway = self.leeway_secs;
        if !self.validate_exp {
            validation.required_spec_claims.remove("exp");
        }
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }

        // Clone the DecodingKey out of the Arc — DecodingKey is Clone and
        // doing the clone here keeps the validation API symmetric with the
        // static-key path. The Arc keeps the heap allocation shared across
        // requests for the same kid until the cache rotates.
        Ok((prepared.key.clone(), validation))
    }

    async fn find_key(self: &Arc<Self>, kid: &str) -> Result<Arc<PreparedKey>, AuthError> {
        match self.cache_lookup(kid) {
            CacheLookup::Hit(prepared) => return Ok(prepared),
            CacheLookup::FreshButMissing => return Err(kid_not_found(kid)),
            CacheLookup::Stale => {}
        }

        // Cancellation-safe single-flight:
        //
        // 1. Acquire fetch_lock to elect a leader.
        // 2. Re-check the cache — another task may have refreshed it
        //    while we waited.
        // 3. Detach the fetch onto a `tokio::spawn`ed task and await its
        //    JoinHandle. If our caller is cancelled, the spawned task
        //    continues to completion and the next request still hits a
        //    fresh cache; without the spawn, cancelling the leader
        //    discards an in-flight fetch and lets followers stampede.
        // 4. Publish the snapshot via ArcSwap; the read path is wait-free.
        let _fetch_guard = self
            .fetch_lock
            .acquire()
            .await
            .map_err(|e| AuthError::BackendError(Box::new(e)))?;

        match self.cache_lookup(kid) {
            CacheLookup::Hit(prepared) => return Ok(prepared),
            CacheLookup::FreshButMissing => return Err(kid_not_found(kid)),
            CacheLookup::Stale => {}
        }

        let store = Arc::clone(self);
        let fetch_task = tokio::spawn(async move {
            let jwks = store.fetch_jwks().await?;
            let prepared = Arc::new(prepare_jwks(&jwks, &store.warned_drops));
            store.cached.store(Some(Arc::clone(&prepared)));
            Ok::<_, AuthError>(prepared)
        });

        let prepared = match fetch_task.await {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(e)) => return Err(e),
            Err(join_err) => {
                return Err(AuthError::BackendError(Box::new(JwksError::FetchTask(
                    join_err,
                ))));
            }
        };

        prepared
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| kid_not_found(kid))
    }

    /// Wait-free hot-path lookup. Returns the prepared key for `kid` if
    /// the cache is fresh, distinguishing a fresh-but-missing kid from
    /// a stale-or-empty cache so the caller knows whether refetching is
    /// warranted. Does not allocate.
    fn cache_lookup(&self, kid: &str) -> CacheLookup {
        let snapshot = self.cached.load();
        let Some(prepared) = snapshot.as_ref() else {
            return CacheLookup::Stale;
        };
        if prepared.fetched_at.elapsed() >= self.cache_ttl {
            return CacheLookup::Stale;
        }
        match prepared.keys.get(kid) {
            Some(key) => CacheLookup::Hit(Arc::clone(key)),
            None => CacheLookup::FreshButMissing,
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AuthError> {
        tracing::debug!(url = %self.url, "Fetching JWKS");

        let response = self
            .http_client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| AuthError::BackendError(Box::new(e)))?;

        if !response.status().is_success() {
            return Err(AuthError::BackendError(Box::new(JwksError::HttpStatus {
                status: response.status(),
            })));
        }

        // Enforce a body-size cap. We can't trust the server's `Content-Length`
        // (it may be missing or wrong), so we accumulate chunks and bail if
        // the total grows beyond the cap.
        let mut body = Vec::with_capacity(4096);
        let mut stream = response;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| AuthError::BackendError(Box::new(e)))?
        {
            if body.len().saturating_add(chunk.len()) > self.max_body_size {
                return Err(AuthError::BackendError(Box::new(JwksError::BodyTooLarge {
                    max_bytes: self.max_body_size,
                })));
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice::<JwkSet>(&body).map_err(|e| AuthError::BackendError(Box::new(e)))
    }
}

/// Convert a freshly fetched [`JwkSet`] into a [`PreparedJwks`] snapshot
/// with `DecodingKey`s built once up front so the hot path doesn't
/// reparse them on every JWT validation.
///
/// Keys that fail to convert are dropped with a warn-level log instead
/// of failing the whole snapshot — one malformed key in a published
/// JWKS document should not take auth down for every kid. The
/// `warned_drops` set deduplicates so the same broken kid does not
/// re-warn on every cache refresh.
fn prepare_jwks(jwks: &JwkSet, warned_drops: &StdMutex<HashSet<String>>) -> PreparedJwks {
    let mut keys: HashMap<String, Arc<PreparedKey>> = HashMap::with_capacity(jwks.keys.len());
    for jwk in &jwks.keys {
        let Some(kid) = jwk.common.key_id.as_deref() else {
            warn_once(warned_drops, "<no-kid>", "no `kid`", || {
                tracing::warn!("Skipping JWKS key with no `kid`");
            });
            continue;
        };
        let Some(algorithm) = jwk
            .common
            .key_algorithm
            .and_then(|a| a.to_string().parse::<Algorithm>().ok())
        else {
            warn_once(warned_drops, kid, "no-usable-alg", || {
                tracing::warn!(
                    kid = %sanitize_for_log(kid),
                    "Skipping JWKS key with no usable `alg`",
                );
            });
            continue;
        };
        match DecodingKey::from_jwk(jwk) {
            Ok(key) => {
                keys.insert(kid.to_string(), Arc::new(PreparedKey { key, algorithm }));
            }
            Err(e) => {
                warn_once(warned_drops, kid, "decode-key-failed", || {
                    tracing::warn!(
                        kid = %sanitize_for_log(kid),
                        error = %e,
                        "Failed to build DecodingKey from JWK; skipping",
                    );
                });
            }
        }
    }
    PreparedJwks {
        fetched_at: Instant::now(),
        keys,
    }
}

/// Emit a warn-level log via the provided closure, but only the first
/// time a given `(kid, reason)` pair is observed for this store.
fn warn_once(
    warned: &StdMutex<HashSet<String>>,
    kid: &str,
    reason: &'static str,
    emit: impl FnOnce(),
) {
    let key = format!("{reason}:{kid}");
    let mut guard = match warned.lock() {
        Ok(g) => g,
        // Mutex poisoned by an unrelated panic; fall through to emit so
        // we never silently swallow JWKS-config warnings just because of
        // an unrelated failure.
        Err(p) => p.into_inner(),
    };
    if guard.insert(key) {
        emit();
    }
}

/// JWT authentication backend.
///
/// Extracts a JWT from the configured [`TokenSource`], validates it
/// using the configured key (static or JWKS), and maps claims to an
/// [`Identity`] using the [`ClaimsMapper`].
pub struct JwtBackend {
    key_resolver: KeyResolver,
    token_source: TokenSource,
    claims_mapper: ClaimsMapperHandle,
}

impl std::fmt::Debug for JwtBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match &self.key_resolver {
            KeyResolver::Static(_) => "static",
            KeyResolver::Jwks(_) => "jwks",
        };
        f.debug_struct("JwtBackend")
            .field("key_mode", &mode)
            .field("token_source", &self.token_source)
            .finish_non_exhaustive()
    }
}

impl JwtBackend {
    /// Create a new builder for configuring the JWT backend.
    pub fn builder() -> JwtBackendBuilder {
        JwtBackendBuilder::default()
    }

    fn extract_token(&self, headers: &http::HeaderMap) -> Option<String> {
        match &self.token_source {
            TokenSource::BearerHeader => {
                let auth = headers.get(http::header::AUTHORIZATION)?;
                let auth_str = auth.to_str().ok()?;
                rusty_gasket::auth::backend::extract_bearer_token(auth_str).map(String::from)
            }
            TokenSource::Cookie(name) => {
                let cookies = headers.get(http::header::COOKIE)?;
                let cookies_str = cookies.to_str().ok()?;
                let prefix = format!("{name}=");
                let mut found: Option<String> = None;
                for pair in cookies_str.split(';') {
                    if let Some(value) = pair.trim().strip_prefix(&prefix) {
                        if found.is_some() {
                            // Two cookies with the same name — refuse to
                            // pick one. Cookie shadowing (via a sibling
                            // path or response splitting) would otherwise
                            // let an attacker substitute a token.
                            tracing::warn!(
                                cookie_name = %name,
                                "Multiple cookies with the same name; refusing to extract a token"
                            );
                            return None;
                        }
                        found = Some(value.to_string());
                    }
                }
                found
            }
            TokenSource::Header(name) => {
                let value = headers.get(name)?;
                let raw = value.to_str().ok()?;
                Some(strip_bearer_prefix(raw).to_string())
            }
        }
    }

    fn decode_jwt_error(e: &jsonwebtoken::errors::Error) -> AuthError {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            jsonwebtoken::errors::ErrorKind::InvalidToken
            | jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                AuthError::InvalidCredentials(format!("Invalid JWT: {e}"))
            }
            _ => AuthError::TokenValidation(format!("JWT validation failed: {e}")),
        }
    }
}

impl AuthBackend for JwtBackend {
    fn name(&self) -> &'static str {
        "jwt"
    }

    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        let token = match self.extract_token(headers) {
            Some(t) => t,
            None => return Ok(None),
        };

        let token_data = match &self.key_resolver {
            KeyResolver::Static(sk) => {
                jsonwebtoken::decode::<serde_json::Value>(&token, &sk.key, &sk.validation)
                    .map_err(|e| Self::decode_jwt_error(&e))?
            }
            KeyResolver::Jwks(store) => {
                let (key, validation) = store.resolve_key(&token).await?;
                jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation)
                    .map_err(|e| Self::decode_jwt_error(&e))?
            }
        };

        let identity = self.claims_mapper.map_claims(&token_data.claims)?;
        Ok(Some(identity))
    }
}

/// Static key material for the JWT backend.
enum StaticKeySource {
    Hmac(Vec<u8>),
    RsaPem(Vec<u8>),
    EcPem(Vec<u8>),
}

/// Builder for [`JwtBackend`].
///
/// Build a backend with one of the key configuration helpers
/// ([`Self::hmac_secret`], [`Self::rsa_pem`], [`Self::ec_pem`], or
/// [`Self::jwks_url`]) and call [`Self::build`].
#[must_use = "JwtBackendBuilder must be consumed by .build() to produce a backend"]
pub struct JwtBackendBuilder {
    static_key: Option<StaticKeySource>,
    jwks_url: Option<String>,
    algorithm: Algorithm,
    token_source: TokenSource,
    claims_mapper: Option<ClaimsMapperHandle>,
    audience: Option<String>,
    issuer: Option<String>,
    validate_exp: bool,
    validate_nbf: bool,
    leeway_secs: u64,
    jwks_cache_ttl: Duration,
    jwks_timeout: Duration,
    jwks_max_body_size: usize,
    jwks_allowed_algorithms: Option<Vec<Algorithm>>,
    jwks_allow_http: bool,
}

impl Default for JwtBackendBuilder {
    fn default() -> Self {
        Self {
            static_key: None,
            jwks_url: None,
            algorithm: Algorithm::HS256,
            token_source: TokenSource::BearerHeader,
            claims_mapper: None,
            audience: None,
            issuer: None,
            validate_exp: true,
            validate_nbf: true,
            leeway_secs: 0,
            jwks_cache_ttl: DEFAULT_JWKS_CACHE_TTL,
            jwks_timeout: DEFAULT_JWKS_TIMEOUT,
            jwks_max_body_size: DEFAULT_JWKS_MAX_BODY_SIZE,
            jwks_allowed_algorithms: None,
            jwks_allow_http: false,
        }
    }
}

impl std::fmt::Debug for JwtBackendBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtBackendBuilder")
            .field("algorithm", &self.algorithm)
            .field("token_source", &self.token_source)
            .field("validate_exp", &self.validate_exp)
            .field("jwks_url", &self.jwks_url)
            .field("jwks_cache_ttl", &self.jwks_cache_ttl)
            .finish_non_exhaustive()
    }
}

impl JwtBackendBuilder {
    /// Default set of allowed algorithms when validating tokens via JWKS.
    ///
    /// Asymmetric algorithms only — HMAC is excluded because JWKS keys
    /// are public and HMAC requires shared secrets.
    fn default_jwks_algorithms() -> Vec<Algorithm> {
        vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::EdDSA,
        ]
    }

    /// Set the HMAC secret for HS256/HS384/HS512 validation.
    pub fn hmac_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.static_key = Some(StaticKeySource::Hmac(secret.into()));
        self
    }

    /// Set an RSA public key in PEM format for RS256/RS384/RS512 validation.
    pub fn rsa_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.static_key = Some(StaticKeySource::RsaPem(pem.into()));
        self.algorithm = Algorithm::RS256;
        self
    }

    /// Set an EC public key in PEM format for ES256/ES384 validation.
    pub fn ec_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.static_key = Some(StaticKeySource::EcPem(pem.into()));
        self.algorithm = Algorithm::ES256;
        self
    }

    /// Set a JWKS endpoint URL for automatic key discovery and rotation.
    ///
    /// Keys are fetched lazily on the first request and cached. The
    /// algorithm is determined from the JWT header's `alg` field, then
    /// validated against the algorithm allow-list (see
    /// [`Self::jwks_allowed_algorithms`]).
    ///
    /// The URL must use `https://` unless [`Self::jwks_allow_http`] is set.
    ///
    /// # Operational note
    ///
    /// Concurrent kid-cache misses coalesce: a single-permit
    /// `tokio::sync::Semaphore` elects one leader to fetch the JWKS,
    /// and followers wait on the resulting cache snapshot rather than
    /// firing their own HTTP requests. The leader's fetch is
    /// `tokio::spawn`ed so that cancellation of the leader's outer
    /// future (e.g. an axum request that timed out) does NOT abort
    /// the fetch — the spawned task keeps running and publishes the
    /// snapshot.
    ///
    /// The dedup is therefore "no per-caller stampede", not "exactly
    /// one upstream fetch ever": in the small window between the
    /// leader's cancellation and its spawned task publishing, the
    /// first arriving follower can fire one redundant fetch. The
    /// total upstream call count for any cache-miss event is bounded
    /// by a small constant (see the
    /// `leader_cancellation_does_not_starve_followers` integration
    /// test for the contract).
    ///
    /// Trade-off: kid-cache misses serialize behind the in-flight
    /// fetch. If the JWKS endpoint hangs (up to the configured
    /// request timeout, default 10 s), every JWT validation needing
    /// a fresh key blocks for the same duration. Configure
    /// [`Self::jwks_timeout`] to bound this and ensure your JWKS
    /// endpoint has a tight latency SLO.
    ///
    /// # Example
    ///
    /// ```ignore
    /// JwtBackend::builder()
    ///     .jwks_url("https://auth.example.com/.well-known/jwks.json")
    ///     .audience("my-api")
    ///     .issuer("https://auth.example.com")
    ///     .build()?
    /// ```
    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    /// Override the JWKS cache TTL (default: 5 minutes).
    pub const fn jwks_cache_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_cache_ttl = ttl;
        self
    }

    /// Override the JWKS HTTP request timeout (default: 10 seconds).
    pub const fn jwks_timeout(mut self, timeout: Duration) -> Self {
        self.jwks_timeout = timeout;
        self
    }

    /// Override the maximum JWKS response body size in bytes (default: 1 MiB).
    pub const fn jwks_max_body_size(mut self, max_bytes: usize) -> Self {
        self.jwks_max_body_size = max_bytes;
        self
    }

    /// Restrict which JWT signing algorithms are accepted from JWKS-issued tokens.
    ///
    /// Defaults to common asymmetric algorithms (RS*, PS*, ES256, ES384, `EdDSA`).
    /// HMAC algorithms are intentionally excluded — JWKS keys are public, and
    /// allowing `HS*` here enables a well-known confused-deputy attack where
    /// an attacker signs a token using the public key as the HMAC secret.
    pub fn jwks_allowed_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = Algorithm>,
    ) -> Self {
        self.jwks_allowed_algorithms = Some(algorithms.into_iter().collect());
        self
    }

    /// Permit fetching JWKS over plaintext HTTP. **Off by default**.
    ///
    /// Only use for local development or trusted-network scenarios where
    /// TLS would otherwise be in the way (e.g., test fixtures).
    pub const fn jwks_allow_http(mut self, allow: bool) -> Self {
        self.jwks_allow_http = allow;
        self
    }

    /// Override the JWT algorithm for static keys (default: HS256/RS256/ES256).
    /// Not used for JWKS — see [`Self::jwks_allowed_algorithms`].
    pub const fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Override where to extract the token from (default: Bearer header).
    pub fn token_source(mut self, source: TokenSource) -> Self {
        self.token_source = source;
        self
    }

    /// Set a custom claims mapper. Default: [`StandardClaimsMapper`].
    pub fn claims_mapper(mut self, mapper: impl ClaimsMapper) -> Self {
        self.claims_mapper = Some(ClaimsMapperHandle::new(mapper));
        self
    }

    /// Set a custom claims mapper handle. Useful for dynamic assembly.
    pub fn claims_mapper_handle(mut self, mapper: ClaimsMapperHandle) -> Self {
        self.claims_mapper = Some(mapper);
        self
    }

    /// Set the expected audience claim.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the expected issuer claim.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Whether to validate the `exp` claim (default: true).
    pub const fn validate_exp(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Whether to validate the `nbf` (not-before) claim (default: true).
    ///
    /// jsonwebtoken defaults `nbf` validation to off; rusty-gasket enables
    /// it because accepting tokens before their stated activation time is
    /// almost never desired in a service context.
    pub const fn validate_nbf(mut self, validate: bool) -> Self {
        self.validate_nbf = validate;
        self
    }

    /// Clock-skew leeway in seconds applied when validating `exp`, `nbf`,
    /// and `iat` (default: 0).
    ///
    /// jsonwebtoken's default leeway is 60 seconds, which permits using
    /// tokens for a full minute past their expiry. The framework defaults
    /// to no leeway and lets the operator opt into a deliberate value.
    pub const fn leeway_secs(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Build the [`JwtBackend`].
    ///
    /// Static keys (HMAC, PEM) are parsed eagerly so configuration errors
    /// surface at startup. JWKS endpoints are connected lazily on the
    /// first request, but the URL scheme and HTTP client are validated here.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Configuration`] when:
    /// - no key source is configured,
    /// - both a static key and a JWKS URL are configured,
    /// - a static key is incompatible with the configured algorithm,
    /// - PEM material is malformed,
    /// - the JWKS URL is not `https://` (without [`Self::jwks_allow_http`]),
    /// - the HTTP client cannot be built (e.g. invalid TLS config).
    pub fn build(self) -> Result<JwtBackend, AuthError> {
        let key_resolver = match (self.static_key.as_ref(), self.jwks_url.as_deref()) {
            (None, None) => {
                return Err(AuthError::Configuration(
                    "JWT key source is required (call hmac_secret, rsa_pem, ec_pem, or jwks_url)"
                        .to_string(),
                ));
            }
            (Some(_), Some(_)) => {
                return Err(AuthError::Configuration(
                    "JWT backend cannot use both a static key and a JWKS URL".to_string(),
                ));
            }
            (Some(static_key), None) => Self::build_static_resolver(static_key, &self)?,
            (None, Some(url)) => Self::build_jwks_resolver(url, &self)?,
        };

        Ok(JwtBackend {
            key_resolver,
            token_source: self.token_source,
            claims_mapper: self
                .claims_mapper
                .unwrap_or_else(|| ClaimsMapperHandle::new(StandardClaimsMapper)),
        })
    }

    fn build_static_resolver(
        source: &StaticKeySource,
        builder: &Self,
    ) -> Result<KeyResolver, AuthError> {
        let validation = builder.build_validation();
        let static_key = match source {
            StaticKeySource::Hmac(secret) => {
                let compatible = matches!(
                    builder.algorithm,
                    Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
                );
                if !compatible {
                    return Err(AuthError::Configuration(format!(
                        "Algorithm {:?} is incompatible with HMAC secret",
                        builder.algorithm
                    )));
                }
                StaticKey {
                    key: DecodingKey::from_secret(secret),
                    validation,
                }
            }
            StaticKeySource::RsaPem(pem) => {
                let compatible = matches!(
                    builder.algorithm,
                    Algorithm::RS256
                        | Algorithm::RS384
                        | Algorithm::RS512
                        | Algorithm::PS256
                        | Algorithm::PS384
                        | Algorithm::PS512
                );
                if !compatible {
                    return Err(AuthError::Configuration(format!(
                        "Algorithm {:?} is incompatible with RSA PEM key",
                        builder.algorithm
                    )));
                }
                let key = DecodingKey::from_rsa_pem(pem)
                    .map_err(|e| AuthError::Configuration(format!("Invalid RSA PEM: {e}")))?;
                StaticKey { key, validation }
            }
            StaticKeySource::EcPem(pem) => {
                let compatible = matches!(builder.algorithm, Algorithm::ES256 | Algorithm::ES384);
                if !compatible {
                    return Err(AuthError::Configuration(format!(
                        "Algorithm {:?} is incompatible with EC PEM key",
                        builder.algorithm
                    )));
                }
                let key = DecodingKey::from_ec_pem(pem)
                    .map_err(|e| AuthError::Configuration(format!("Invalid EC PEM: {e}")))?;
                StaticKey { key, validation }
            }
        };
        Ok(KeyResolver::Static(Box::new(static_key)))
    }

    fn build_jwks_resolver(url: &str, builder: &Self) -> Result<KeyResolver, AuthError> {
        // Parse the URL so we reject malformed inputs (`https:// `,
        // `https:///foo`, scheme-only) and so the scheme + host checks
        // are robust against case and trailing whitespace.
        let parsed = ::url::Url::parse(url).map_err(|e| {
            AuthError::Configuration(format!(
                "JWKS URL is not a valid absolute URL ({e}); got {url:?}"
            ))
        })?;
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(AuthError::Configuration(format!(
                "JWKS URL has no host: {url:?}"
            )));
        }
        match parsed.scheme() {
            "https" => {}
            "http" if builder.jwks_allow_http => {}
            "http" => {
                return Err(AuthError::Configuration(format!(
                    "JWKS URL must use https:// (got {url:?}); call jwks_allow_http(true) to opt out"
                )));
            }
            other => {
                return Err(AuthError::Configuration(format!(
                    "JWKS URL scheme must be http or https (got {other:?})"
                )));
            }
        }

        // Reject redirects: an attacker who poisons DNS, controls a
        // CDN, or owns one redirect hop could otherwise serve
        // attacker-controlled JWKS JSON (and even downgrade an https
        // origin to http on the redirect target, defeating the
        // `jwks_allow_http(false)` check above). Operators that
        // legitimately need redirects must canonicalize the URL up
        // front; the framework will not follow them silently.
        let http_client = reqwest::Client::builder()
            .timeout(builder.jwks_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                AuthError::Configuration(format!("Failed to build JWKS HTTP client: {e}"))
            })?;

        let allowed_algorithms = builder
            .jwks_allowed_algorithms
            .clone()
            .unwrap_or_else(Self::default_jwks_algorithms);

        if allowed_algorithms.is_empty() {
            return Err(AuthError::Configuration(
                "JWKS allowed_algorithms must not be empty".to_string(),
            ));
        }

        let store = JwksKeyStore {
            url: url.to_string(),
            cache_ttl: builder.jwks_cache_ttl,
            cached: ArcSwapOption::const_empty(),
            fetch_lock: Semaphore::new(1),
            http_client,
            max_body_size: builder.jwks_max_body_size,
            allowed_algorithms,
            audience: builder.audience.clone(),
            issuer: builder.issuer.clone(),
            validate_exp: builder.validate_exp,
            validate_nbf: builder.validate_nbf,
            leeway_secs: builder.leeway_secs,
            warned_drops: StdMutex::new(HashSet::new()),
        };
        Ok(KeyResolver::Jwks(Arc::new(store)))
    }

    fn build_validation(&self) -> Validation {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = self.validate_exp;
        validation.validate_nbf = self.validate_nbf;
        validation.leeway = self.leeway_secs;
        if !self.validate_exp {
            validation.required_spec_claims.remove("exp");
        }
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }
        validation
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_for_log_strips_control_bytes_and_truncates() {
        // Newlines, carriage returns, and ANSI escape bytes must not flow
        // into an AuthError that gets %-formatted into a log line.
        let attacker = "bad\nINFO fake_user logged_in\r\nx\u{1b}[1mboldhack\u{1b}[0m";
        let sanitized = sanitize_for_log(attacker);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\u{1b}'));
        assert!(sanitized.starts_with("bad"));

        // Truncation at 128 chars stops a token-sized payload from
        // dumping its full body into log lines.
        let big: String = std::iter::repeat_n('a', 1024).collect();
        assert_eq!(sanitize_for_log(&big).len(), 128);
    }

    #[test]
    fn kid_not_found_error_does_not_contain_control_bytes() {
        let err = kid_not_found("evil\nfake\r\nlog line");
        let s = err.to_string();
        assert!(!s.contains('\n'), "rendered error contains newline: {s:?}");
        assert!(!s.contains('\r'), "rendered error contains CR: {s:?}");
    }

    #[test]
    fn strip_bearer_prefix_handles_common_cases() {
        // No prefix → returned as-is (after trim).
        assert_eq!(strip_bearer_prefix("eyJabc.def.ghi"), "eyJabc.def.ghi");
        // Standard prefix.
        assert_eq!(
            strip_bearer_prefix("Bearer eyJabc.def.ghi"),
            "eyJabc.def.ghi"
        );
        // Case-insensitive.
        assert_eq!(
            strip_bearer_prefix("bearer eyJabc.def.ghi"),
            "eyJabc.def.ghi"
        );
        assert_eq!(
            strip_bearer_prefix("BEARER eyJabc.def.ghi"),
            "eyJabc.def.ghi"
        );
        // Leading whitespace ahead of the prefix is tolerated.
        assert_eq!(
            strip_bearer_prefix("  Bearer eyJabc.def.ghi"),
            "eyJabc.def.ghi"
        );
        // Multiple spaces between prefix and token are collapsed.
        assert_eq!(
            strip_bearer_prefix("Bearer   eyJabc.def.ghi"),
            "eyJabc.def.ghi"
        );
        // A bare token starting with the letters "Bearer" (no following
        // space) is *not* a prefix and must not be stripped — would yield
        // a corrupt token otherwise.
        assert_eq!(strip_bearer_prefix("BearerLikeWord"), "BearerLikeWord");
    }

    #[test]
    fn oauth_claims_mapper_preserves_client_id_by_default() {
        let claims = serde_json::json!({
            "sub": "oauth_client:svc-a",
            "client_id": "svc-a",
            "scope": "read write",
            "name": "Service A",
        });

        let identity = OAuthClaimsMapper::new()
            .map_claims(&claims)
            .expect("map oauth claims");

        assert_eq!(identity.subject(), "oauth_client:svc-a");
        assert_eq!(identity.auth_method(), "oauth-jwt");
        assert_eq!(identity.display_name(), Some("Service A"));
        assert!(identity.has_scope("read"));
        assert!(identity.has_scope("write"));
        assert_eq!(
            identity
                .attributes()
                .get::<OAuthTokenClaims>()
                .and_then(OAuthTokenClaims::client_id),
            Some("svc-a")
        );
    }

    #[test]
    fn oauth_claims_mapper_can_ignore_client_id() {
        let claims = serde_json::json!({
            "sub": "oauth_client:svc-a",
            "client_id": "svc-a",
        });

        let identity = OAuthClaimsMapper::new()
            .ignore_client_id()
            .map_claims(&claims)
            .expect("map oauth claims");

        assert!(identity.attributes().get::<OAuthTokenClaims>().is_none());
    }

    fn make_test_backend() -> JwtBackend {
        JwtBackend::builder()
            .hmac_secret(b"test-secret-key-that-is-long-enough")
            .validate_exp(false)
            .build()
            .expect("valid builder")
    }

    fn make_test_token(claims: &serde_json::Value) -> String {
        let header = jsonwebtoken::Header::new(Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(b"test-secret-key-that-is-long-enough");
        jsonwebtoken::encode(&header, claims, &key).expect("encode token")
    }

    #[tokio::test]
    async fn valid_bearer_token() {
        let backend = make_test_backend();
        let token = make_test_token(&serde_json::json!({
            "sub": "user-123",
            "scope": "read write",
            "name": "Test User",
        }));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("valid header"),
        );

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "user-123");
        assert_eq!(identity.auth_method(), "jwt");
        assert_eq!(identity.display_name(), Some("Test User"));
        assert!(identity.has_scope("read"));
        assert!(identity.has_scope("write"));
        assert!(!identity.has_scope("admin"));
    }

    #[tokio::test]
    async fn no_auth_header_returns_none() {
        let backend = make_test_backend();
        let headers = http::HeaderMap::new();

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await
            .expect("should succeed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn invalid_token_returns_error() {
        let backend = make_test_backend();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer not-a-valid-jwt".parse().expect("valid header"),
        );

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wrong_secret_returns_error() {
        let backend = JwtBackend::builder()
            .hmac_secret(b"different-secret-key-that-is-long-enough")
            .validate_exp(false)
            .build()
            .expect("valid builder");

        let token = make_test_token(&serde_json::json!({"sub": "user-123"}));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("valid header"),
        );

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn missing_sub_claim_returns_error() {
        let backend = make_test_backend();
        let token = make_test_token(&serde_json::json!({"scope": "read"}));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("valid header"),
        );

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn builder_requires_key_source() {
        let result = JwtBackend::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_static_and_jwks() {
        let result = JwtBackend::builder()
            .hmac_secret(b"a-very-long-test-secret-key-please")
            .jwks_url("https://example.com/jwks.json")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn jwks_url_requires_https_by_default() {
        let result = JwtBackend::builder()
            .jwks_url("http://example.com/jwks.json")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn jwks_url_rejects_unknown_scheme() {
        let result = JwtBackend::builder()
            .jwks_url("file:///etc/passwd")
            .jwks_allow_http(true)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn jwks_url_allows_http_when_opted_in() {
        let result = JwtBackend::builder()
            .jwks_url("http://localhost:8080/jwks.json")
            .jwks_allow_http(true)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn jwks_empty_allowed_algorithms_rejected() {
        let result = JwtBackend::builder()
            .jwks_url("https://example.com/jwks.json")
            .jwks_allowed_algorithms(vec![])
            .build();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cookie_token_source() {
        let backend = JwtBackend::builder()
            .hmac_secret(b"test-secret-key-that-is-long-enough")
            .token_source(TokenSource::Cookie("auth_token".to_string()))
            .validate_exp(false)
            .build()
            .expect("valid builder");

        let token = make_test_token(&serde_json::json!({"sub": "cookie-user"}));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("auth_token={token}; other=value")
                .parse()
                .expect("valid header"),
        );

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "cookie-user");
    }

    #[test]
    fn jwks_builder_creates_backend() {
        let backend = JwtBackend::builder()
            .jwks_url("https://auth.example.com/.well-known/jwks.json")
            .audience("my-api")
            .issuer("https://auth.example.com")
            .build();

        assert!(backend.is_ok());
        let backend = backend.expect("should build");
        assert!(matches!(backend.key_resolver, KeyResolver::Jwks(_)));
    }

    #[test]
    fn jwks_cache_ttl_takes_effect_regardless_of_call_order() {
        // Set TTL before jwks_url to confirm it is preserved.
        let backend = JwtBackend::builder()
            .jwks_cache_ttl(Duration::from_secs(42))
            .jwks_url("https://auth.example.com/jwks.json")
            .build()
            .expect("valid builder");

        let KeyResolver::Jwks(store) = &backend.key_resolver else {
            panic!("expected JWKS resolver");
        };
        assert_eq!(store.cache_ttl, Duration::from_secs(42));
    }
}
