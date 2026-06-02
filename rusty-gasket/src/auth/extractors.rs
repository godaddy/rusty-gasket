//! Axum extractors for accessing authentication state in handlers.
//!
//! - [`Authenticated`] — requires a valid identity (returns 401 if absent)
//! - [`CurrentUser`] — readable alias for the authenticated caller
//! - [`RequireScope`] — requires a named OAuth/API scope
//! - [`ServiceAccount`] — requires service-to-service automation
//! - [`SuperuserOnly`] — requires a privileged identity
//! - [`OptionalIdentity`] — provides the identity if present, `None` otherwise

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use rusty_gasket::auth::context::AuthContext;
use rusty_gasket::auth::identity::Identity;

/// Axum extractor that requires an authenticated caller.
///
/// Extracts the [`Identity`] from the [`AuthContext`] that the auth
/// middleware inserts into request extensions. Returns the framework's
/// standard JSON `ErrorResponse` with status 401 (`AUTHENTICATION_REQUIRED`)
/// when no identity is present — handlers do not need to special-case
/// the auth failure shape.
///
/// # Example
///
/// ```no_run
/// use rusty_gasket::auth::Authenticated;
/// use axum::response::IntoResponse;
///
/// async fn handler(Authenticated(identity): Authenticated) -> impl IntoResponse {
///     format!("Hello, {}", identity.subject())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Authenticated(pub Identity);

/// Readable extractor for the authenticated caller.
///
/// This is intentionally a separate type from [`Authenticated`]. Generated API
/// code can use `CurrentUser` when the handler needs the caller as a domain
/// concept, while lower-level auth examples can still use `Authenticated`.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub Identity);

/// Axum extractor that optionally provides an identity.
///
/// Returns `Some(Identity)` if the caller is authenticated,
/// `None` if anonymous. Never fails — use this for routes that
/// serve both authenticated and unauthenticated users.
#[derive(Debug, Clone)]
pub struct OptionalIdentity(pub Option<Identity>);

/// Error returned when `Authenticated` extractor fails.
#[derive(Debug)]
pub struct AuthRequired;

/// Error returned when authorization policy rejects an authenticated caller.
#[derive(Debug, Clone)]
pub struct AuthorizationRequired {
    code: &'static str,
    message: String,
}

/// Marker trait for compile-time named scope guards.
///
/// Stable Rust does not allow string const generics, so
/// `RequireScope<"orders:write">` is not currently possible. The stable,
/// readable shape is a marker type:
///
/// ```ignore
/// struct OrdersWrite;
/// impl RequiredScope for OrdersWrite {
///     const SCOPE: &'static str = "orders:write";
/// }
///
/// async fn create_order(_scope: RequireScope<OrdersWrite>) {}
/// ```
pub trait RequiredScope: Send + Sync + 'static {
    /// Scope required by this guard.
    const SCOPE: &'static str;
}

/// Extractor that requires the authenticated identity to carry one scope.
///
/// Use a marker type implementing [`RequiredScope`] to name the scope in a way
/// that remains readable in handler signatures.
#[derive(Debug, Clone)]
pub struct RequireScope<Scope> {
    identity: Identity,
    scope: PhantomData<Scope>,
}

impl<Scope> RequireScope<Scope> {
    /// Borrow the identity that satisfied the scope guard.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Consume the guard and return the authenticated identity.
    #[must_use]
    pub fn into_identity(self) -> Identity {
        self.identity
    }
}

impl<Scope> Deref for RequireScope<Scope> {
    type Target = Identity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

/// Extractor that requires a service-to-service identity.
#[derive(Debug, Clone)]
pub struct ServiceAccount(pub Identity);

/// Extractor that requires a privileged/superuser identity.
#[derive(Debug, Clone)]
pub struct SuperuserOnly(pub Identity);

impl IntoResponse for AuthRequired {
    fn into_response(self) -> Response {
        rusty_gasket::error::quick_error_response(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "Missing or invalid credentials. Authentication is required for this endpoint.",
        )
    }
}

impl IntoResponse for AuthorizationRequired {
    fn into_response(self) -> Response {
        rusty_gasket::error::quick_error_response(StatusCode::FORBIDDEN, self.code, &self.message)
    }
}

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
{
    type Rejection = AuthRequired;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ctx = parts.extensions.get::<AuthContext>().ok_or(AuthRequired)?;

        ctx.identity()
            .cloned()
            .map(Authenticated)
            .ok_or(AuthRequired)
    }
}

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = AuthRequired;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Authenticated::from_request_parts(parts, state)
            .await
            .map(|Authenticated(identity)| Self(identity))
    }
}

impl<S> FromRequestParts<S> for OptionalIdentity
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let identity = parts
            .extensions
            .get::<AuthContext>()
            .and_then(|ctx| ctx.identity().cloned());

        Ok(Self(identity))
    }
}

impl<S, Scope> FromRequestParts<S> for RequireScope<Scope>
where
    S: Send + Sync,
    Scope: RequiredScope,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated(identity) = Authenticated::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if identity.has_scope(Scope::SCOPE) {
            Ok(Self {
                identity,
                scope: PhantomData,
            })
        } else {
            Err(AuthorizationRequired {
                code: "MISSING_SCOPE",
                message: format!("Missing required scope '{}'.", Scope::SCOPE),
            }
            .into_response())
        }
    }
}

impl<S> FromRequestParts<S> for ServiceAccount
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated(identity) = Authenticated::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if identity.is_service_account() {
            Ok(Self(identity))
        } else {
            Err(AuthorizationRequired {
                code: "SERVICE_ACCOUNT_REQUIRED",
                message: "This endpoint requires a service account.".to_owned(),
            }
            .into_response())
        }
    }
}

impl<S> FromRequestParts<S> for SuperuserOnly
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated(identity) = Authenticated::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if identity.is_privileged() {
            Ok(Self(identity))
        } else {
            Err(AuthorizationRequired {
                code: "SUPERUSER_REQUIRED",
                message: "This endpoint requires a privileged identity.".to_owned(),
            }
            .into_response())
        }
    }
}
