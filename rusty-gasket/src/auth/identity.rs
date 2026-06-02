//! Verified caller identity.
//!
//! [`Identity`] is the framework's universal "who is this caller?" type.
//! It is backend-agnostic: a JWT, an API key, or an OIDC token all produce
//! the same `Identity`. Backend-specific data can be attached via the
//! typed `attributes` extension map.

use std::collections::HashSet;

/// A verified identity produced by an authentication backend.
///
/// This is the framework's universal "who is this caller?" type. It is
/// backend-agnostic: a JWT, an API key, or an OIDC token all produce
/// the same `Identity`. Backend-specific data can be attached via the
/// typed `attributes` extension map.
///
/// Fields are private after construction to prevent accidental mutation
/// of scopes or subject by downstream handlers. Use the builder-style
/// methods on `IdentityBuilder` or `Identity::new()` to construct.
#[derive(Debug, Clone)]
pub struct Identity {
    subject: String,
    auth_method: &'static str,
    display_name: Option<String>,
    scopes: HashSet<String>,
    service_account: bool,
    privileged: bool,
    attributes: http::Extensions,
}

impl Identity {
    /// Create a minimal identity with just a subject and method.
    #[must_use]
    pub fn new(subject: impl Into<String>, auth_method: &'static str) -> Self {
        Self {
            subject: subject.into(),
            auth_method,
            display_name: None,
            scopes: HashSet::new(),
            service_account: false,
            privileged: false,
            attributes: http::Extensions::new(),
        }
    }

    /// Create an identity builder for more complex construction.
    pub fn builder(subject: impl Into<String>, auth_method: &'static str) -> IdentityBuilder {
        IdentityBuilder {
            identity: Self::new(subject, auth_method),
        }
    }

    /// Primary identifier for the caller.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Which authentication method produced this identity.
    #[must_use]
    pub const fn auth_method(&self) -> &'static str {
        self.auth_method
    }

    /// Optional human-readable name for logging and display.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Scopes or permissions granted by the credential.
    #[must_use]
    pub const fn scopes(&self) -> &HashSet<String> {
        &self.scopes
    }

    /// Whether this identity has elevated/superuser privileges.
    ///
    /// Backends decide what privileged means for them: a superuser client
    /// allowlist, an admin scope, a specific issuer, etc. The framework
    /// only consumes this flag for observability (it appears as the
    /// `is_privileged` field on the request span) so SIEM rules can
    /// flag privileged actions.
    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        self.privileged
    }

    /// Whether this identity represents service-to-service automation.
    ///
    /// Auth backends set this flag when the credential is a machine/service
    /// account rather than a human-delegated user token. Handlers should use
    /// the [`ServiceAccount`](rusty_gasket::auth::ServiceAccount) extractor when they need
    /// this policy enforced before business logic starts.
    #[must_use]
    pub const fn is_service_account(&self) -> bool {
        self.service_account
    }

    /// Typed extension map for backend-specific data.
    ///
    /// Organization-specific overlays can attach custom claims here.
    /// Downstream code extracts by type:
    /// `identity.attributes().get::<MyCustomClaims>()`.
    #[must_use]
    pub const fn attributes(&self) -> &http::Extensions {
        &self.attributes
    }

    /// Mutable access to the extension map.
    ///
    /// Useful for wrapper backends that augment an identity produced by an
    /// inner backend (e.g. attaching organization-specific token metadata
    /// after JWT validation has succeeded).
    pub const fn attributes_mut(&mut self) -> &mut http::Extensions {
        &mut self.attributes
    }

    /// Mark this identity as privileged. See [`Identity::is_privileged`].
    ///
    /// Useful for wrapper backends that decide privilege after the inner
    /// backend has produced an identity (e.g. an org-specific superuser
    /// allowlist applied on top of JWT validation).
    pub const fn set_privileged(&mut self, privileged: bool) {
        self.privileged = privileged;
    }

    /// Mark this identity as a service account.
    pub const fn set_service_account(&mut self, service_account: bool) {
        self.service_account = service_account;
    }

    /// Check whether this identity has a specific scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// Check whether this identity has all of the given scopes.
    #[must_use]
    pub fn has_all_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|s| self.scopes.contains(*s))
    }

    /// Check whether this identity has any of the given scopes.
    #[must_use]
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|s| self.scopes.contains(*s))
    }
}

/// Builder for constructing `Identity` instances with optional fields.
#[derive(Debug)]
#[must_use = "IdentityBuilder must be consumed by .build() to produce an Identity"]
pub struct IdentityBuilder {
    identity: Identity,
}

impl IdentityBuilder {
    /// Set the display name.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.identity.display_name = Some(name.into());
        self
    }

    /// Add a single scope.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.identity.scopes.insert(scope.into());
        self
    }

    /// Add multiple scopes.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.identity
            .scopes
            .extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Mark the identity as privileged. See [`Identity::is_privileged`].
    pub const fn privileged(mut self, privileged: bool) -> Self {
        self.identity.privileged = privileged;
        self
    }

    /// Mark the identity as service-to-service automation.
    pub const fn service_account(mut self, service_account: bool) -> Self {
        self.identity.service_account = service_account;
        self
    }

    /// Insert a typed attribute.
    pub fn attribute<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.identity.attributes.insert(value);
        self
    }

    /// Consume the builder and return the identity.
    #[must_use]
    pub fn build(self) -> Identity {
        self.identity
    }
}
