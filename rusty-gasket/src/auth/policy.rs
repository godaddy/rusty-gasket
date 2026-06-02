//! Authorization policies.
//!
//! Policies decide whether an authenticated (or anonymous) caller is
//! permitted to perform an action on a resource. The built-in
//! [`ScopePolicy`] checks OAuth scopes; custom policies can implement
//! RBAC, ABAC, or any other authorization model.

use std::future::Future;

use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// An authorization policy that decides whether an authenticated (or
/// anonymous) caller is permitted to perform a specific action on a resource.
///
/// # Return contract
///
/// - `Ok(Allow)` — the caller is authorized
/// - `Ok(Deny { reason })` — the caller is explicitly denied (insufficient
///   scopes, wrong role, etc.)
/// - `Err(AuthError)` — an infrastructure failure prevented the check
///   (database down, misconfigured policy, etc.)
///
/// All authorization denials should use `Ok(Deny)`, not `Err`. Reserve
/// `Err` for cases where the policy itself could not run.
pub trait AuthzPolicy: Send + Sync + 'static {
    /// Check whether the given identity is authorized.
    ///
    /// `resource` and `action` are opaque strings whose meaning is
    /// application-defined (e.g., resource="users", action="delete").
    fn authorize<'ctx>(
        &'ctx self,
        identity: Option<&'ctx Identity>,
        resource: &'ctx str,
        action: &'ctx str,
        ctx: &'ctx AuthzContext,
    ) -> impl Future<Output = Result<AuthzDecision, AuthError>> + Send + 'ctx;
}

/// Additional context available during authorization decisions.
///
/// Construct via [`AuthzContext::new`]. Marked `#[non_exhaustive]` so
/// future fields (e.g., target resource type, tenant id, query params)
/// can be added without breaking downstream `AuthzPolicy` implementations.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthzContext {
    /// HTTP method of the request being authorized.
    pub request_method: http::Method,
    /// Request path (for path-based authorization rules).
    pub request_path: String,
}

impl AuthzContext {
    /// Create an `AuthzContext` describing the request being authorized.
    #[must_use]
    pub fn new(request_method: http::Method, request_path: impl Into<String>) -> Self {
        Self {
            request_method,
            request_path: request_path.into(),
        }
    }
}

/// The result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzDecision {
    /// The caller is authorized to proceed.
    Allow,
    /// The caller is denied access.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
}

/// How scopes are matched against requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeMatchMode {
    /// Identity must have ALL required scopes.
    All,
    /// Identity must have at least ONE required scope.
    Any,
}

/// Scope-based authorization policy.
///
/// Requires the identity to have specific scopes. Commonly used to
/// protect endpoints that need particular OAuth scopes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScopePolicy {
    /// The scopes that must be present on the caller's identity.
    pub required_scopes: Vec<String>,
    /// Whether all scopes are required or just one.
    pub match_mode: ScopeMatchMode,
}

impl ScopePolicy {
    /// Create a policy that requires the caller to have ALL of the given scopes.
    #[must_use]
    pub fn require_all<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            required_scopes: scopes.into_iter().map(Into::into).collect(),
            match_mode: ScopeMatchMode::All,
        }
    }

    /// Create a policy that requires the caller to have at least ONE of the given scopes.
    #[must_use]
    pub fn require_any<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            required_scopes: scopes.into_iter().map(Into::into).collect(),
            match_mode: ScopeMatchMode::Any,
        }
    }
}

impl AuthzPolicy for ScopePolicy {
    async fn authorize(
        &self,
        identity: Option<&Identity>,
        _resource: &str,
        _action: &str,
        _ctx: &AuthzContext,
    ) -> Result<AuthzDecision, AuthError> {
        let identity = match identity {
            Some(id) => id,
            None => {
                return Ok(AuthzDecision::Deny {
                    reason: "Authentication required".to_string(),
                });
            }
        };

        let satisfied = match self.match_mode {
            ScopeMatchMode::All => self
                .required_scopes
                .iter()
                .all(|s| identity.scopes().contains(s)),
            ScopeMatchMode::Any => self
                .required_scopes
                .iter()
                .any(|s| identity.scopes().contains(s)),
        };

        if satisfied {
            Ok(AuthzDecision::Allow)
        } else {
            let missing: Vec<&str> = self
                .required_scopes
                .iter()
                .filter(|s| !identity.scopes().contains(s.as_str()))
                .map(String::as_str)
                .collect();

            Ok(AuthzDecision::Deny {
                reason: format!("Missing required scopes: {}", missing.join(", ")),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(scopes: &[&str]) -> Identity {
        Identity::builder("test-user", "test")
            .scopes(scopes.iter().map(|s| (*s).to_string()))
            .build()
    }

    fn make_ctx() -> AuthzContext {
        AuthzContext::new(http::Method::GET, "/test")
    }

    #[tokio::test]
    async fn scope_policy_all_satisfied() {
        let policy = ScopePolicy::require_all(vec!["read".to_string(), "write".to_string()]);
        let id = make_identity(&["read", "write", "admin"]);
        let ctx = make_ctx();

        let result = policy
            .authorize(Some(&id), "resource", "action", &ctx)
            .await
            .expect("should not error");
        assert_eq!(result, AuthzDecision::Allow);
    }

    #[tokio::test]
    async fn scope_policy_all_missing_one() {
        let policy = ScopePolicy::require_all(vec!["read".to_string(), "write".to_string()]);
        let id = make_identity(&["read"]);
        let ctx = make_ctx();

        let result = policy
            .authorize(Some(&id), "resource", "action", &ctx)
            .await
            .expect("policy check should not fail");
        assert!(
            matches!(result, AuthzDecision::Deny { .. }),
            "missing scope should deny, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn scope_policy_any_satisfied() {
        let policy = ScopePolicy::require_any(vec!["admin".to_string(), "write".to_string()]);
        let id = make_identity(&["write"]);
        let ctx = make_ctx();

        let result = policy
            .authorize(Some(&id), "resource", "action", &ctx)
            .await
            .expect("should not error");
        assert_eq!(result, AuthzDecision::Allow);
    }

    #[tokio::test]
    async fn scope_policy_any_none_present() {
        let policy = ScopePolicy::require_any(vec!["admin".to_string(), "write".to_string()]);
        let id = make_identity(&["read"]);
        let ctx = make_ctx();

        let result = policy
            .authorize(Some(&id), "resource", "action", &ctx)
            .await
            .expect("policy check should not fail");
        assert!(
            matches!(result, AuthzDecision::Deny { .. }),
            "missing scope should deny, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn scope_policy_no_identity() {
        let policy = ScopePolicy::require_all(vec!["read".to_string()]);
        let ctx = make_ctx();

        let result = policy
            .authorize(None, "resource", "action", &ctx)
            .await
            .expect("should return deny, not error");
        assert_eq!(
            result,
            AuthzDecision::Deny {
                reason: "Authentication required".to_string()
            }
        );
    }
}
