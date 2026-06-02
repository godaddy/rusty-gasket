//! API key authentication backend.
//!
//! Extracts an API key from a request header or query parameter and
//! validates it via a user-provided [`ApiKeyValidator`].

use std::future::Future;

use rusty_gasket::BoxFuture;

use rusty_gasket::auth::backend::AuthBackend;
use rusty_gasket::auth::error::AuthError;
use rusty_gasket::auth::identity::Identity;

/// Where to extract the API key from the request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ApiKeySource {
    /// Custom header name (e.g., "X-API-Key").
    Header(String),
    /// Query parameter name (e.g., "api_key").
    QueryParam(String),
}

/// Validates an API key and returns an identity if valid.
///
/// Implementations might look up the key in a database, an in-memory
/// map, or a remote service.
pub trait ApiKeyValidator: Send + Sync + 'static {
    /// Validate an API key and return the associated identity, or `None` if the key is unknown.
    fn validate<'ctx>(
        &'ctx self,
        key: &'ctx str,
    ) -> impl Future<Output = Result<Option<Identity>, AuthError>> + Send + 'ctx;
}

trait ErasedApiKeyValidator: Send + Sync + 'static {
    fn validate<'ctx>(
        &'ctx self,
        key: &'ctx str,
    ) -> BoxFuture<'ctx, Result<Option<Identity>, AuthError>>;
}

impl<T> ErasedApiKeyValidator for T
where
    T: ApiKeyValidator,
{
    fn validate<'ctx>(
        &'ctx self,
        key: &'ctx str,
    ) -> BoxFuture<'ctx, Result<Option<Identity>, AuthError>> {
        Box::pin(ApiKeyValidator::validate(self, key))
    }
}

/// API key authentication backend.
///
/// Extracts an API key from a header or query parameter and validates
/// it using the configured `ApiKeyValidator`.
pub struct ApiKeyBackend {
    source: ApiKeySource,
    validator: Box<dyn ErasedApiKeyValidator>,
}

impl std::fmt::Debug for ApiKeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyBackend")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl ApiKeyBackend {
    /// Create a new API key backend with the given source and validator.
    pub fn new(source: ApiKeySource, validator: impl ApiKeyValidator) -> Self {
        Self {
            source,
            validator: Box::new(validator),
        }
    }

    fn extract_key(&self, headers: &http::HeaderMap, uri: &http::Uri) -> Option<String> {
        match &self.source {
            ApiKeySource::Header(name) => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            ApiKeySource::QueryParam(param) => uri.query().and_then(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .find(|(key, _)| key == param)
                    .map(|(_, value)| value.into_owned())
            }),
        }
    }
}

impl AuthBackend for ApiKeyBackend {
    fn name(&self) -> &'static str {
        "api-key"
    }

    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        uri: &http::Uri,
    ) -> Result<Option<Identity>, AuthError> {
        let key = match self.extract_key(headers, uri) {
            Some(k) => k,
            None => return Ok(None),
        };

        self.validator.validate(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticValidator {
        valid_key: String,
        identity: Identity,
    }

    impl ApiKeyValidator for StaticValidator {
        async fn validate(&self, key: &str) -> Result<Option<Identity>, AuthError> {
            if key == self.valid_key {
                Ok(Some(self.identity.clone()))
            } else {
                Err(AuthError::InvalidCredentials("Invalid API key".to_string()))
            }
        }
    }

    fn make_backend() -> ApiKeyBackend {
        ApiKeyBackend::new(
            ApiKeySource::Header("X-API-Key".to_string()),
            StaticValidator {
                valid_key: "valid-key-123".to_string(),
                identity: Identity::new("api-client", "api-key"),
            },
        )
    }

    #[tokio::test]
    async fn valid_api_key_header() {
        let backend = make_backend();
        let mut headers = http::HeaderMap::new();
        headers.insert("X-API-Key", "valid-key-123".parse().expect("valid header"));

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "api-client");
    }

    #[tokio::test]
    async fn no_api_key_returns_none() {
        let backend = make_backend();
        let headers = http::HeaderMap::new();

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await
            .expect("should succeed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn invalid_api_key_returns_error() {
        let backend = make_backend();
        let mut headers = http::HeaderMap::new();
        headers.insert("X-API-Key", "wrong-key".parse().expect("valid header"));

        let result = backend
            .authenticate(&headers, &"/test".parse().expect("valid uri"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn query_param_extraction() {
        let backend = ApiKeyBackend::new(
            ApiKeySource::QueryParam("api_key".to_string()),
            StaticValidator {
                valid_key: "query-key".to_string(),
                identity: Identity::new("query-client", "api-key"),
            },
        );
        let headers = http::HeaderMap::new();

        let result = backend
            .authenticate(
                &headers,
                &"/test?api_key=query-key".parse().expect("valid uri"),
            )
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "query-client");
    }

    #[tokio::test]
    async fn url_encoded_api_key_in_query_param() {
        let backend = ApiKeyBackend::new(
            ApiKeySource::QueryParam("api_key".to_string()),
            StaticValidator {
                valid_key: "key with spaces".to_string(),
                identity: Identity::new("encoded-client", "api-key"),
            },
        );
        let headers = http::HeaderMap::new();

        let result = backend
            .authenticate(
                &headers,
                &"/test?api_key=key%20with%20spaces"
                    .parse()
                    .expect("valid uri"),
            )
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "encoded-client");
    }

    #[tokio::test]
    async fn plus_sign_decoded_as_space_in_query_param() {
        let backend = ApiKeyBackend::new(
            ApiKeySource::QueryParam("api_key".to_string()),
            StaticValidator {
                valid_key: "key with spaces".to_string(),
                identity: Identity::new("plus-client", "api-key"),
            },
        );
        let headers = http::HeaderMap::new();

        let result = backend
            .authenticate(
                &headers,
                &"/test?api_key=key+with+spaces".parse().expect("valid uri"),
            )
            .await
            .expect("should succeed");

        let identity = result.expect("should have identity");
        assert_eq!(identity.subject(), "plus-client");
    }
}
