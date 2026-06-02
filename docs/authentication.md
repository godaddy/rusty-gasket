# Authentication

Pluggable authentication and authorization system with JWT, API key, and chain-based multi-backend support.

The authentication API is designed for generated service code that backend engineers can still read and maintain without being Rust specialists. Custom backends use ordinary `async fn`, auth chains are assembled with builders, and the framework hides boxed futures and dynamic dispatch behind named handles.

## Overview

Enable the `auth` feature on the public `rusty-gasket` crate to use:

- **`AuthBackend` trait** -- interface for authentication backends
- **`JwtBackend`** -- JWT validation (HMAC, RSA, EC)
- **`ApiKeyBackend`** -- API key validation via header or query parameter
- **`AuthChain`** -- compose multiple backends, first match wins
- **Axum extractors** -- `Authenticated`, `CurrentUser`, and `OptionalIdentity`
- **Authorization guards** -- `RequireScope`, `ServiceAccount`, and `SuperuserOnly`
- **Authorization policies** -- `ScopePolicy` for lower-level custom checks
- **Audit logging** -- `AuditLogger` trait for security event recording
- **Testing** -- `MockAuthBackend` for integration tests

## AuthBackend Trait

Every authentication backend implements this trait:

```rust
pub trait AuthBackend: Send + Sync + 'static {
    /// Short, stable name (e.g., "jwt", "api-key"). Used in logs and metrics.
    fn name(&self) -> &'static str;

    /// Attempt to authenticate from request headers and URI.
    ///
    /// Returns:
    /// - Ok(Some(identity)) -- authentication succeeded
    /// - Ok(None) -- this backend does not apply (no matching credentials found)
    /// - Err(AuthError) -- definitive failure (bad token, expired, etc.)
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError>;
}
```

The three-way return type is important: `Ok(None)` means "I don't handle this request" and lets the chain try the next backend. `Err(...)` means "credentials were found but are invalid" and stops the chain immediately.

## Identity

`Identity` is the framework's universal "who is this caller?" type. It is backend-agnostic.

```rust
pub struct Identity {
    subject: String,              // primary identifier
    auth_method: &'static str,    // which backend produced this ("jwt", "api-key", etc.)
    display_name: Option<String>, // human-readable name
    scopes: HashSet<String>,      // OAuth scopes or permissions
    attributes: http::Extensions, // typed extension map for custom data
}
```

### Construction

Simple:

```rust
let id = Identity::new("user-123", "jwt");
```

With builder:

```rust
let id = Identity::builder("user-123", "jwt")
    .display_name("Jane Doe")
    .scope("read")
    .scope("write")
    .scopes(vec!["admin".to_string()])
    .attribute(MyCustomClaims { tenant_id: "t-1".into() })
    .build();
```

### Querying

```rust
id.subject()                     // "user-123"
id.auth_method()                 // "jwt"
id.display_name()                // Some("Jane Doe")
id.has_scope("read")             // true
id.has_all_scopes(&["read", "write"])  // true
id.has_any_scope(&["admin", "superuser"])  // true
id.attributes().get::<MyCustomClaims>()    // Some(&MyCustomClaims { ... })
```

## JWT Backend

Validates JSON Web Tokens using the `jsonwebtoken` crate. Supports HMAC (HS256/384/512), RSA (RS256/384/512), and EC (ES256/384) algorithms.

### OAuth Claims Mapping

Use `OAuthClaimsMapper` when a JWT is an OAuth-style access token and policy code needs to read the issuing client application.

```rust
use rusty_gasket::auth::backends::jwt::{JwtBackend, OAuthClaimsMapper};

let backend = JwtBackend::builder()
    .jwks_url("https://auth.example.com/.well-known/jwks.json")
    .issuer("https://auth.example.com")
    .claims_mapper(OAuthClaimsMapper::new())
    .build()?;
```

The mapper keeps the readable default JWT behavior:

- `sub` becomes `Identity::subject()`
- `scope` becomes identity scopes
- `name` becomes `Identity::display_name()`
- `client_id` is preserved as typed metadata for policy wrappers

If a service does not want `client_id` metadata, make that explicit:

```rust
let mapper = OAuthClaimsMapper::new().ignore_client_id();
```

### Builder Pattern

```rust
use rusty_gasket::auth::backends::jwt::JwtBackend;

// HMAC secret (HS256)
let backend = JwtBackend::builder()
    .hmac_secret(b"your-secret-key")
    .audience("my-api")
    .issuer("https://auth.example.com")
    .build()?;

// RSA public key (RS256)
let backend = JwtBackend::builder()
    .rsa_pem(include_bytes!("public_key.pem"))
    .algorithm(jsonwebtoken::Algorithm::RS256)
    .audience("my-api")
    .build()?;

// EC public key (ES256)
let backend = JwtBackend::builder()
    .ec_pem(include_bytes!("ec_public.pem"))
    .build()?;
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `hmac_secret(secret)` | Set HMAC secret for HS256/384/512 |
| `rsa_pem(pem)` | Set RSA public key (PEM format), sets algorithm to RS256 |
| `ec_pem(pem)` | Set EC public key (PEM format), sets algorithm to ES256 |
| `algorithm(alg)` | Override the algorithm (default: auto-detected from key type) |
| `audience(aud)` | Set expected audience claim |
| `issuer(iss)` | Set expected issuer claim |
| `validate_exp(bool)` | Enable/disable `exp` claim validation (default: true) |
| `token_source(source)` | Where to extract the token (default: Bearer header) |
| `claims_mapper(mapper)` | Custom claims-to-identity mapping |
| `build()` | Build the backend (validates key/algorithm compatibility) |

### Token Sources

```rust
use rusty_gasket::auth::backends::jwt::TokenSource;

// Default: Authorization: Bearer <token>
JwtBackend::builder().token_source(TokenSource::BearerHeader)
```

// From a cookie
JwtBackend::builder().token_source(TokenSource::Cookie("auth_token".into()))

// From a custom header
JwtBackend::builder().token_source(TokenSource::Header("X-Auth-Token".into()))
```

### Custom Claims Mapping

The default `StandardClaimsMapper` maps standard JWT claims:
- `sub` -> `Identity.subject` (required)
- `scope` (space-separated string) -> `Identity.scopes`
- `name` -> `Identity.display_name`

For custom claim structures, implement `ClaimsMapper`:

```rust
use rusty_gasket::auth::backends::jwt::ClaimsMapper;

struct MyClaimsMapper;

impl ClaimsMapper for MyClaimsMapper {
    fn map_claims(&self, claims: &serde_json::Value) -> Result<Identity, AuthError> {
        let subject = claims["sub"].as_str()
            .ok_or_else(|| AuthError::TokenValidation("Missing sub".into()))?;
        let tenant = claims["tenant_id"].as_str().unwrap_or("default");

        Ok(Identity::builder(subject, "jwt")
            .attribute(TenantId(tenant.to_string()))
            .build())
    }
}

JwtBackend::builder()
    .hmac_secret(secret)
    .claims_mapper(MyClaimsMapper)
    .build()?
```

## API Key Backend

Validates API keys from a header or query parameter using a custom validator.

```rust
use rusty_gasket::auth::backends::api_key::{ApiKeyBackend, ApiKeySource, ApiKeyValidator};

struct MyKeyValidator { /* database pool, etc. */ }

impl ApiKeyValidator for MyKeyValidator {
    async fn validate(&self, key: &str) -> Result<Option<Identity>, AuthError> {
        // Look up key in database, return identity if valid
        if key == "valid-key" {
            Ok(Some(Identity::new("api-client-1", "api-key")))
        } else {
            Err(AuthError::InvalidCredentials("Unknown API key".into()))
        }
    }
}

// From a header
let backend = ApiKeyBackend::new(
    ApiKeySource::Header("X-API-Key".into()),
    MyKeyValidator { /* ... */ },
);

// From a query parameter
let backend = ApiKeyBackend::new(
    ApiKeySource::QueryParam("api_key".into()),
    MyKeyValidator { /* ... */ },
);
```

## AuthChain

Composes multiple backends. Backends are tried in registration order; the first one returning `Ok(Some(identity))` wins.

```rust
use rusty_gasket::auth::{AuthChain, UnauthenticatedPolicy};

let chain = AuthChain::new()
    .backend(jwt_backend)
    .backend(api_key_backend);
```

### Fallback Policy

When no backend produces an identity, the `UnauthenticatedPolicy` determines what happens:

```rust
// Reject unauthenticated requests (default)
let chain = AuthChain::new(backends)
    .with_fallback(UnauthenticatedPolicy::Reject);

// Allow anonymous access (for routes serving both authenticated and anonymous users)
let chain = AuthChain::new(backends)
    .with_fallback(UnauthenticatedPolicy::AllowAnonymous);
```

### Chain Behavior

| Backend returns | Chain action |
|----------------|-------------|
| `Ok(Some(identity))` | Stop, use this identity |
| `Ok(None)` | Try next backend |
| `Err(AuthError)` | Stop, return error immediately |
| All return `Ok(None)` | Apply fallback policy |

## Auth Middleware

The auth middleware runs the `AuthChain` against each request and populates `AuthContext` in request extensions:

```rust
use rusty_gasket::auth::{AuthMiddlewareState, auth_middleware};

let state = Arc::new(
    AuthMiddlewareState::new(chain)
        .with_audit_logger(TracingAuditLogger),
);

// Applied to Protected routes via a TaggedLayer:
TaggedLayer::new(
    MiddlewareSlot::Authentication,
    move |router: Router| {
        router.layer(axum::middleware::from_fn_with_state(state, auth_middleware))
    },
)
```

The middleware also:
- Populates `LoggingContext` so auth fields appear in the logging span (bidirectional middleware communication)
- Extracts client IP from `X-Real-IP` > `X-Forwarded-For` > connection info
- Emits audit log events via the `AuditLogger` (if configured)

## Extractors

### Authenticated

Requires a valid identity. Returns 401 if no identity is present in request extensions.

```rust
use rusty_gasket::auth::Authenticated;

async fn protected_handler(Authenticated(identity): Authenticated) -> String {
    format!("Hello, {}", identity.subject())
}
```

### CurrentUser

Readable alias for the authenticated caller. Prefer this in generated
application handlers when the identity is part of the business logic.

```rust
use rusty_gasket::auth::CurrentUser;

async fn profile(CurrentUser(user): CurrentUser) -> String {
    format!("Hello, {}", user.subject())
}
```

### OptionalIdentity

Provides the identity if present, `None` otherwise. Never fails.

```rust
use rusty_gasket::auth::OptionalIdentity;

async fn public_handler(OptionalIdentity(identity): OptionalIdentity) -> String {
    match identity {
        Some(id) => format!("Hello, {}", id.subject()),
        None => "Hello, anonymous".to_string(),
    }
}
```

### Policy Guards

Use policy guards when a route should not run unless authorization passes.
This keeps authorization visible in the handler signature.

```rust
use rusty_gasket::auth::{RequireScope, RequiredScope, ServiceAccount, SuperuserOnly};

struct OrdersWrite;

impl RequiredScope for OrdersWrite {
    const SCOPE: &'static str = "orders:write";
}

async fn create_order(_scope: RequireScope<OrdersWrite>) {}

async fn service_backfill(_service: ServiceAccount) {}

async fn admin_report(_superuser: SuperuserOnly) {}
```

Stable Rust does not support `RequireScope<"orders:write">`; marker types are
the stable, expert-defensible compromise.

## ScopePolicy

Checks whether the caller has required OAuth scopes:

```rust
use rusty_gasket::auth::{ScopePolicy, ScopeMatchMode, AuthzPolicy, AuthzContext, AuthzDecision};

// Require ALL scopes
let policy = ScopePolicy::require_all(vec![
    "read:users".into(),
    "write:users".into(),
]);

// Require ANY scope
let policy = ScopePolicy::require_any(vec![
    "admin".into(),
    "superuser".into(),
]);

// Use in a handler
async fn admin_action(Authenticated(identity): Authenticated) -> impl IntoResponse {
    let policy = ScopePolicy::require_all(vec!["admin".into()]);
    let ctx = AuthzContext {
        request_method: http::Method::POST,
        request_path: "/admin/action".into(),
    };

    match policy.authorize(Some(&identity), "admin", "action", &ctx).await {
        Ok(AuthzDecision::Allow) => { /* proceed */ },
        Ok(AuthzDecision::Deny { reason }) => { /* forbidden */ },
        Err(e) => { /* scope check failed */ },
    }
}
```

### Custom Authorization Policies

Implement `AuthzPolicy` for RBAC, ABAC, or any other authorization model:

```rust
pub trait AuthzPolicy: Send + Sync + 'static {
    async fn authorize(
        &self,
        identity: Option<&Identity>,
        resource: &str,
        action: &str,
        ctx: &AuthzContext,
    ) -> Result<AuthzDecision, AuthError>;
}
```

## AuditLogger

Records authentication outcomes for security monitoring:

```rust
pub trait AuditLogger: Send + Sync + 'static {
    fn log_auth_event(&self, event: &AuthAuditEvent);
}
```

The `AuthAuditEvent` contains:
- `request_id` -- correlation ID
- `client_ip` -- extracted from headers/connection
- `auth_method` -- which backend handled it
- `subject` -- authenticated caller (if successful)
- `outcome` -- `Success`, `Anonymous`, `Denied { reason }`, or `Error { error }`

The built-in `TracingAuditLogger` writes structured events via `tracing`:

```rust
let state = AuthMiddlewareState {
    chain,
    audit_logger: Some(Arc::new(TracingAuditLogger)),
};
```

## AuthError

Covers all failure modes:

| Variant | HTTP Status | Description |
|---------|-------------|-------------|
| `MissingCredentials` | 401 | No credentials found |
| `InvalidCredentials` | 401 | Credentials present but invalid |
| `TokenExpired` | 401 | JWT `exp` in the past |
| `TokenValidation` | 401 | JWT structure/signature invalid |
| `InsufficientScope` | 403 | Missing required scopes |
| `AuthorizationDenied` | 403 | Policy explicitly denied |
| `BackendError` | 500 | Internal backend failure |
| `Configuration` | 500 | Misconfiguration |

Client error messages (401/403) are fixed strings to avoid leaking internal details. Full error details are logged server-side.

## Testing with MockAuthBackend

`MockAuthBackend` from `rusty_gasket::testing` always returns a fixed identity without real token validation:

```rust
use rusty_gasket::testing::{MockAuthBackend, TestApp};

// Always authenticated as "test-user"
let app = TestApp::builder()
    .with_mock_auth("test-user")
    .router(my_router)
    .build();

// With custom identity (scopes, display name, etc.)
let identity = Identity::builder("admin", "mock")
    .scope("admin")
    .scope("read")
    .display_name("Test Admin")
    .build();

let app = TestApp::builder()
    .with_mock_auth_identity(identity)
    .router(my_router)
    .build();

// Anonymous access
let app = TestApp::builder()
    .with_anonymous_auth()
    .router(my_router)
    .build();
```

See [testing.md](testing.md) for the full testing guide.

## Further Reading

- [Middleware](middleware.md) -- how auth middleware fits in the pipeline
- [Observability](observability.md) -- how auth fields appear in logs
- [Testing](testing.md) -- `TestApp` and `MockAuthBackend`
