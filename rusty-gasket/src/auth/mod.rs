//! Authentication and authorization framework for Rusty Gasket.
//!
//! Provides a pluggable auth backend system ([`AuthBackend`]), a chain that
//! tries multiple backends in order ([`AuthChain`]), axum middleware and
//! extractors, scope-based authorization policies, and audit logging.
//!
//! Built-in backends (behind feature flags):
//! - `jwt` — JWT validation via the `jsonwebtoken` crate
//! - `api-key` — API key validation via a custom validator trait

mod audit;
pub mod backend;
pub mod backends;
mod chain;
mod context;
mod error;
mod extractors;
mod identity;
mod middleware;
mod policy;

pub use audit::{
    AuditLogger, AuditLoggerHandle, AuthAuditEvent, AuthAuditOutcome, IntoAuditLoggerHandle,
    TracingAuditLogger,
};
pub use backend::{AuthBackend, AuthBackendHandle, BoxAuthBackend};
pub use backends::jwt::{JwtBackend, JwtBackendBuilder};
pub use backends::static_bearer::StaticBearerBackend;
pub use chain::{AuthChain, UnauthenticatedPolicy};
pub use context::{AuthContext, AuthResult, FailedReason};
pub use error::AuthError;
pub use extractors::{
    AuthRequired, Authenticated, AuthorizationRequired, CurrentUser, OptionalIdentity,
    RequireScope, RequiredScope, ServiceAccount, SuperuserOnly,
};
pub use identity::{Identity, IdentityBuilder};
pub use middleware::{AuthMiddlewareState, auth_middleware};
pub use policy::{AuthzContext, AuthzDecision, AuthzPolicy, ScopeMatchMode, ScopePolicy};
pub use rusty_gasket::BoxError;

/// Re-exports of the most commonly used auth types.
///
/// Import `use rusty_gasket::auth::prelude::*` to get the auth types
/// you need for implementing backends and using extractors.
pub mod prelude {
    pub use rusty_gasket::BoxError;
    pub use rusty_gasket::auth::backend::{AuthBackend, AuthBackendHandle};
    pub use rusty_gasket::auth::backends::static_bearer::StaticBearerBackend;
    pub use rusty_gasket::auth::chain::{AuthChain, UnauthenticatedPolicy};
    pub use rusty_gasket::auth::error::AuthError;
    pub use rusty_gasket::auth::extractors::{
        Authenticated, CurrentUser, OptionalIdentity, RequireScope, RequiredScope, ServiceAccount,
        SuperuserOnly,
    };
    pub use rusty_gasket::auth::identity::Identity;
    pub use rusty_gasket::auth::middleware::{AuthMiddlewareState, auth_middleware};
    pub use rusty_gasket::auth::{AuditLogger, AuditLoggerHandle, TracingAuditLogger};
}
