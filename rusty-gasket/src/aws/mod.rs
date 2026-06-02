//! AWS integrations for Rusty Gasket.
//!
//! This crate contains standards-based AWS integrations that are useful
//! outside any one company deployment. Organization overlays can re-export
//! these types with their own defaults without owning the implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Weak;
use std::time::{Duration, Instant};

use rusty_gasket::BoxError;
use rusty_gasket::config::{SecretValue, SecretsProvider};
use tokio::sync::{RwLock, Semaphore};

#[cfg(feature = "s3")]
#[cfg_attr(docsrs, doc(cfg(feature = "s3")))]
pub mod s3;
#[cfg(feature = "s3")]
pub use s3::{ObjectMeta, S3ObjectStore};

/// Default cache TTL when [`AwsSecretsProvider::builder`] is not given
/// an explicit one.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// `SecretsProvider` implementation backed by AWS Secrets Manager.
///
/// The provider caches string secrets in memory and uses a per-secret
/// single-flight lock on cache misses. If many requests ask for the same
/// expired secret at once, exactly one request fetches from AWS while the
/// rest wait for the refreshed value. Different secret names still fetch
/// independently.
pub struct AwsSecretsProvider {
    client: aws_sdk_secretsmanager::Client,
    cache: Arc<RwLock<HashMap<String, CachedSecret>>>,
    inflight: Arc<RwLock<HashMap<String, Weak<Semaphore>>>>,
    cache_ttl: Duration,
}

/// Cached secret value plus the instant it was fetched.
struct CachedSecret {
    value: String,
    fetched_at: Instant,
}

impl std::fmt::Debug for AwsSecretsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSecretsProvider")
            .field("cache_ttl", &self.cache_ttl)
            .finish_non_exhaustive()
    }
}

/// Builder for [`AwsSecretsProvider`].
///
/// Use [`AwsSecretsProvider::builder`] to construct one. The terminal
/// methods choose between an explicit SDK client and a client loaded from
/// the default AWS SDK config chain.
#[derive(Debug, Default)]
#[must_use = "AwsSecretsProviderBuilder does nothing until `build` or `build_from_env` is called"]
pub struct AwsSecretsProviderBuilder {
    cache_ttl: Option<Duration>,
}

impl AwsSecretsProviderBuilder {
    /// Override the cache TTL. Defaults to five minutes.
    pub const fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Build with an explicit Secrets Manager client.
    ///
    /// This is the right constructor for tests, LocalStack, custom
    /// endpoints, or applications that already centralize AWS SDK setup.
    #[must_use]
    pub fn build(self, client: aws_sdk_secretsmanager::Client) -> AwsSecretsProvider {
        AwsSecretsProvider {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            inflight: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: self.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL),
        }
    }

    /// Build from the default AWS SDK config chain.
    ///
    /// Region and credentials come from the normal AWS SDK sources:
    /// environment, config files, web identity, IMDS, ECS task role, and
    /// the other providers supported by the SDK.
    pub async fn build_from_env(self) -> AwsSecretsProvider {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        self.build(aws_sdk_secretsmanager::Client::new(&config))
    }
}

impl AwsSecretsProvider {
    /// Start configuring an [`AwsSecretsProvider`].
    pub fn builder() -> AwsSecretsProviderBuilder {
        AwsSecretsProviderBuilder::default()
    }

    /// Build from the default AWS SDK config chain with default cache settings.
    pub async fn from_env() -> Self {
        Self::builder().build_from_env().await
    }

    /// Read through the cache and fetch from AWS on a miss.
    async fn get_secret_inner(&self, key: &str) -> Result<Option<SecretValue>, BoxError> {
        if let Some(value) = self.read_cache(key).await {
            return Ok(Some(value));
        }

        // Coalesce concurrent callers for the same key. The permit is
        // intentionally per-secret name, so unrelated secrets can still
        // refresh in parallel.
        let semaphore = self.get_or_create_fetch_lock(key).await;
        let permit = semaphore
            .acquire()
            .await
            .map_err(|e| format!("AWS Secrets Manager fetch lock closed for '{key}': {e}"))?;

        // Re-check under the permit. Another caller may have refreshed the
        // cache while this request waited.
        if let Some(value) = self.read_cache(key).await {
            return Ok(Some(value));
        }

        let outcome = self.fetch_secret_from_aws(key).await;

        // Drop both strong references before pruning. The inflight map
        // stores weak references, so pruning only works after this function
        // stops holding the semaphore.
        drop(permit);
        drop(semaphore);
        self.prune_inflight(key).await;
        outcome
    }

    /// Return a cached secret if the value is still inside its TTL.
    async fn read_cache(&self, key: &str) -> Option<SecretValue> {
        let cache = self.cache.read().await;
        cache.get(key).and_then(|cached| {
            (cached.fetched_at.elapsed() < self.cache_ttl)
                .then(|| SecretValue::new(cached.value.clone()))
        })
    }

    /// Fetch a secret string from AWS and update the in-memory cache.
    async fn fetch_secret_from_aws(&self, key: &str) -> Result<Option<SecretValue>, BoxError> {
        let result = self.client.get_secret_value().secret_id(key).send().await;
        match result {
            Ok(output) => {
                let value = output
                    .secret_string()
                    .ok_or_else(|| format!("Secret '{key}' has no string value"))?
                    .to_owned();

                self.cache.write().await.insert(
                    key.to_owned(),
                    CachedSecret {
                        value: value.clone(),
                        fetched_at: Instant::now(),
                    },
                );

                Ok(Some(SecretValue::new(value)))
            }
            Err(error) => {
                use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
                if let Some(service_error) = error.as_service_error()
                    && matches!(
                        service_error,
                        GetSecretValueError::ResourceNotFoundException(_)
                    )
                {
                    Ok(None)
                } else {
                    Err(format!("AWS Secrets Manager error for '{key}': {error}").into())
                }
            }
        }
    }

    /// Get the single-flight semaphore for this secret name.
    async fn get_or_create_fetch_lock(&self, key: &str) -> Arc<Semaphore> {
        if let Some(semaphore) = self.inflight.read().await.get(key).and_then(Weak::upgrade) {
            return semaphore;
        }

        let mut map = self.inflight.write().await;
        if let Some(semaphore) = map.get(key).and_then(Weak::upgrade) {
            return semaphore;
        }

        let semaphore = Arc::new(Semaphore::new(1));
        map.insert(key.to_owned(), Arc::downgrade(&semaphore));
        semaphore
    }

    /// Remove an expired weak single-flight entry after the fetch completes.
    async fn prune_inflight(&self, key: &str) {
        let mut map = self.inflight.write().await;
        if map.get(key).is_some_and(|weak| weak.strong_count() == 0) {
            map.remove(key);
        }
    }
}

impl SecretsProvider for AwsSecretsProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<SecretValue>, BoxError> {
        self.get_secret_inner(key).await
    }
}
