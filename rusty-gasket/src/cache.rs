//! Novice-friendly caching for API services.
//!
//! The public surface is intentionally small:
//! [`ObjectCache`] stores arbitrary serializable values by [`CacheKey`], while
//! [`cached_get`] and [`ResponseCachePolicy`] cache whole HTTP responses for
//! read-only endpoints. The backend clients stay hidden so application code can
//! talk in API concepts instead of Redis, Memcached, Moka, or Tower plumbing.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::handler::Handler;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::{BoxError, BoxFuture};

const DEFAULT_CACHE_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_RESPONSE_CACHE_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_MEMCACHED_KEY_BYTES: usize = 250;

/// Result type returned by cache operations.
pub type CacheResult<T> = Result<T, CacheError>;

/// Errors from object-cache configuration, serialization, and backends.
///
/// Loader errors are wrapped separately from backend failures so callers can
/// distinguish "the thing I tried to compute failed" from "the cache system
/// failed." Response caching treats cache failures as fail-open and logs them.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// Cache configuration was invalid or requested an unavailable backend.
    #[error("Cache configuration is invalid: {0}")]
    InvalidConfig(String),

    /// A cache key cannot be used by the configured backend.
    #[error("Cache key is invalid: {0}")]
    InvalidKey(String),

    /// A value could not be serialized before writing to the cache.
    #[error("Failed to encode cached value")]
    Encode(#[source] serde_json::Error),

    /// A cached value could not be deserialized into the requested type.
    #[error("Failed to decode cached value")]
    Decode(#[source] serde_json::Error),

    /// The caller-provided loader failed while computing a missing value.
    #[error("Cache loader failed")]
    Loader(#[source] BoxError),

    /// The selected backend failed while reading, writing, or deleting data.
    #[error("Cache backend failed: {0}")]
    Backend(String),
}

/// How long a value should remain cacheable.
///
/// The wrapper keeps function signatures readable and lets config parse
/// friendly strings such as `"30s"`, `"5m"`, and `"128 MiB"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtl(Duration);

impl CacheTtl {
    /// Create a TTL from a [`Duration`].
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// Create a TTL from seconds.
    #[must_use]
    pub const fn seconds(seconds: u64) -> Self {
        Self(Duration::from_secs(seconds))
    }

    /// Create a TTL from minutes.
    #[must_use]
    pub const fn minutes(minutes: u64) -> Self {
        Self(Duration::from_secs(minutes.saturating_mul(60)))
    }

    /// Borrow the wrapped duration for lower-level APIs.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl Default for CacheTtl {
    fn default() -> Self {
        Self(DEFAULT_CACHE_TTL)
    }
}

impl From<Duration> for CacheTtl {
    fn from(duration: Duration) -> Self {
        Self(duration)
    }
}

impl<'de> Deserialize<'de> for CacheTtl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DurationText::deserialize(deserializer).map(|duration| Self(duration.0))
    }
}

impl Serialize for CacheTtl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}s", self.0.as_secs()))
    }
}

/// Cache key builder that keeps key composition explicit and unambiguous.
///
/// `CacheKey::new("products").part(product_id).part("summary")` produces a
/// stable, delimiter-safe key while avoiding ad hoc `format!` strings in app
/// code. Key parts are percent-encoded so user input cannot accidentally create
/// collisions with neighboring parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey(String);

impl CacheKey {
    /// Start a key with the named cache area, such as `"products"`.
    #[must_use]
    pub fn new(area: impl AsRef<str>) -> Self {
        Self(encode_key_part(area.as_ref()))
    }

    /// Add another key part. Each part is encoded before being appended.
    #[must_use]
    pub fn part(mut self, value: impl ToString) -> Self {
        self.0.push(':');
        self.0.push_str(&encode_key_part(&value.to_string()));
        self
    }

    /// Borrow the canonical cache key string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the key and return the canonical string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<&str> for CacheKey {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Eviction policy used by the in-process cache.
///
/// Moka uses a Caffeine-inspired admission and eviction policy. Rusty Gasket
/// names that policy `TinyLfu` because that is the important operational
/// property for API teams: frequently used entries survive better than entries
/// that were only touched recently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CacheAlgorithm {
    /// Frequency-aware bounded cache, backed by Moka for in-process storage.
    #[default]
    TinyLfu,
}

/// Cache backend selected by configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CacheBackendKind {
    /// In-process cache. Best default for local development and simple APIs.
    #[default]
    Memory,
    /// Redis or Valkey through the `redis` crate. Requires `cache-redis`.
    Redis,
    /// Memcached through `memcache-async`. Requires `cache-memcached`.
    Memcached,
}

/// Redis connection settings for the object cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RedisCacheConfig {
    /// Redis URL, for example `redis://127.0.0.1/`.
    pub url: String,
}

/// Memcached connection settings for the object cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemcachedCacheConfig {
    /// TCP server addresses such as `"127.0.0.1:11211"`.
    pub servers: Vec<String>,
}

/// Config for the default object cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct CacheConfig {
    /// Backend to use. Defaults to in-process memory.
    pub backend: CacheBackendKind,
    /// Eviction algorithm for backends that support local eviction.
    pub algorithm: CacheAlgorithm,
    /// Maximum memory budget for the in-process cache.
    pub max_memory: MemoryBudget,
    /// Default TTL used when callers do not choose one.
    pub default_ttl: CacheTtl,
    /// Prefix applied to every backend key so services do not collide.
    pub namespace: String,
    /// Whether concurrent misses for the same key are coalesced in-process.
    pub single_flight: bool,
    /// Redis settings used when `backend = "redis"`.
    pub redis: Option<RedisCacheConfig>,
    /// Memcached settings used when `backend = "memcached"`.
    pub memcached: Option<MemcachedCacheConfig>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackendKind::Memory,
            algorithm: CacheAlgorithm::TinyLfu,
            max_memory: MemoryBudget(DEFAULT_CACHE_MEMORY_BYTES),
            default_ttl: CacheTtl::default(),
            namespace: "rusty-gasket".to_string(),
            single_flight: true,
            redis: None,
            memcached: None,
        }
    }
}

impl CacheConfig {
    /// Build the default in-process cache configuration.
    #[must_use]
    pub fn memory() -> Self {
        Self::default()
    }

    /// Override the maximum in-process memory budget.
    #[must_use]
    pub const fn max_memory(mut self, max_memory: MemoryBudget) -> Self {
        self.max_memory = max_memory;
        self
    }

    /// Override the default TTL.
    #[must_use]
    pub const fn default_ttl(mut self, default_ttl: CacheTtl) -> Self {
        self.default_ttl = default_ttl;
        self
    }
}

/// Memory budget parsed from config.
///
/// Accepts integer byte counts or strings such as `"64 MiB"`, `"512kb"`, and
/// `"1 gb"`. It intentionally stores bytes because cache capacity must be a
/// real bound, not a vague item count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryBudget(u64);

impl MemoryBudget {
    /// Create a memory budget from raw bytes.
    #[must_use]
    pub const fn bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Create a memory budget from mebibytes.
    #[must_use]
    pub const fn mebibytes(mebibytes: u64) -> Self {
        Self(mebibytes.saturating_mul(1024 * 1024))
    }

    /// Return the configured budget in bytes.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        self.0
    }
}

impl Serialize for MemoryBudget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for MemoryBudget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        MemoryBudgetText::deserialize(deserializer).map(|budget| Self(budget.0))
    }
}

/// Object cache for arbitrary serializable data.
///
/// Application code should normally keep one `ObjectCache` in its
/// `AppServices` context and call [`Self::get_or_load`] from service methods.
/// The cache handles serialization, key namespacing, backend calls, and
/// in-process single-flight miss protection.
#[derive(Clone)]
pub struct ObjectCache {
    backend: Arc<dyn CacheBackend>,
    namespace: Arc<str>,
    default_ttl: CacheTtl,
    single_flight: bool,
    in_flight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

impl std::fmt::Debug for ObjectCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectCache")
            .field("namespace", &self.namespace)
            .field("default_ttl", &self.default_ttl)
            .field("single_flight", &self.single_flight)
            .finish_non_exhaustive()
    }
}

impl ObjectCache {
    /// Create an in-process object cache with safe defaults.
    #[must_use]
    pub fn memory() -> Self {
        Self::from_memory_config(CacheConfig::memory())
    }

    /// Create an in-process object cache from config.
    #[must_use]
    pub fn from_memory_config(config: CacheConfig) -> Self {
        let backend = MemoryCacheBackend::new(config.max_memory);
        Self::from_backend(config, backend)
    }

    /// Create an object cache from config, including optional external backends.
    ///
    /// # Errors
    /// Returns an error if the selected backend is unavailable, missing required
    /// settings, or cannot connect during initialization.
    pub async fn from_config(config: CacheConfig) -> CacheResult<Self> {
        match config.backend {
            CacheBackendKind::Memory => Ok(Self::from_memory_config(config)),
            CacheBackendKind::Redis => Self::from_redis_config(config).await,
            CacheBackendKind::Memcached => Self::from_memcached_config(config).await,
        }
    }

    /// Read a typed value from the cache.
    ///
    /// # Errors
    /// Returns an error if the backend fails or the cached bytes cannot be
    /// decoded as `T`.
    pub async fn get<T>(&self, key: CacheKey) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned,
    {
        let key = self.namespaced_key(&key)?;
        let Some(bytes) = self.backend.get(&key).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(CacheError::Decode)
    }

    /// Store a typed value using the cache's default TTL.
    ///
    /// # Errors
    /// Returns an error if serialization fails or the backend write fails.
    pub async fn set<T>(&self, key: CacheKey, value: &T) -> CacheResult<()>
    where
        T: Serialize,
    {
        self.set_for(key, self.default_ttl, value).await
    }

    /// Store a typed value for the provided TTL.
    ///
    /// # Errors
    /// Returns an error if serialization fails or the backend write fails.
    pub async fn set_for<T>(&self, key: CacheKey, ttl: CacheTtl, value: &T) -> CacheResult<()>
    where
        T: Serialize,
    {
        let key = self.namespaced_key(&key)?;
        let bytes = serde_json::to_vec(value).map_err(CacheError::Encode)?;
        self.backend.set(&key, bytes.into(), ttl).await
    }

    /// Delete a value from the cache.
    ///
    /// # Errors
    /// Returns an error if the backend delete fails.
    pub async fn delete(&self, key: CacheKey) -> CacheResult<()> {
        let key = self.namespaced_key(&key)?;
        self.backend.delete(&key).await
    }

    /// Get a value or compute and store it on a miss.
    ///
    /// Concurrent misses for the same key are coalesced by default: one caller
    /// runs the loader while other callers wait and then read the populated
    /// value. That prevents a cold or expired key from stampeding an upstream
    /// database or API.
    ///
    /// # Errors
    /// Returns backend/serialization errors, or wraps the loader's error in
    /// [`CacheError::Loader`].
    pub async fn get_or_load<T, Load, LoadFuture, LoadError>(
        &self,
        key: CacheKey,
        ttl: CacheTtl,
        load: Load,
    ) -> CacheResult<T>
    where
        T: Serialize + DeserializeOwned,
        Load: FnOnce() -> LoadFuture,
        LoadFuture: Future<Output = Result<T, LoadError>>,
        LoadError: Into<BoxError>,
    {
        if !self.single_flight {
            return self.get_or_load_without_single_flight(key, ttl, load).await;
        }

        loop {
            if let Some(value) = self.get(key.clone()).await? {
                return Ok(value);
            }

            let namespaced_key = self.namespaced_key(&key)?;
            let wait_for_leader = {
                let mut in_flight = self.in_flight.lock().await;
                if let Some(notify) = in_flight.get(&namespaced_key) {
                    Some(Arc::clone(notify))
                } else {
                    in_flight.insert(namespaced_key.clone(), Arc::new(Notify::new()));
                    None
                }
            };

            if let Some(notify) = wait_for_leader {
                notify.notified().await;
                continue;
            }

            let load_result = load()
                .await
                .map_err(|error| CacheError::Loader(error.into()));
            let final_result = match load_result {
                Ok(value) => match self.set_for(key, ttl, &value).await {
                    Ok(()) => Ok(value),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };

            self.finish_in_flight(&namespaced_key).await;
            return final_result;
        }
    }

    async fn get_or_load_without_single_flight<T, Load, LoadFuture, LoadError>(
        &self,
        key: CacheKey,
        ttl: CacheTtl,
        load: Load,
    ) -> CacheResult<T>
    where
        T: Serialize + DeserializeOwned,
        Load: FnOnce() -> LoadFuture,
        LoadFuture: Future<Output = Result<T, LoadError>>,
        LoadError: Into<BoxError>,
    {
        if let Some(value) = self.get(key.clone()).await? {
            return Ok(value);
        }

        let value = load()
            .await
            .map_err(|error| CacheError::Loader(error.into()))?;
        self.set_for(key, ttl, &value).await?;
        Ok(value)
    }

    async fn finish_in_flight(&self, key: &str) {
        let notify = self.in_flight.lock().await.remove(key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    fn from_backend(config: CacheConfig, backend: impl CacheBackend + 'static) -> Self {
        Self {
            backend: Arc::new(backend),
            namespace: Arc::from(config.namespace),
            default_ttl: config.default_ttl,
            single_flight: config.single_flight,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn namespaced_key(&self, key: &CacheKey) -> CacheResult<String> {
        let namespace = encode_key_part(&self.namespace);
        let key = format!("{namespace}:{}", key.as_str());
        validate_backend_key(&key)?;
        Ok(key)
    }

    #[cfg(feature = "cache-redis")]
    async fn from_redis_config(config: CacheConfig) -> CacheResult<Self> {
        let redis = config.redis.as_ref().ok_or_else(|| {
            CacheError::InvalidConfig("redis backend requires cache.redis.url".to_string())
        })?;
        let backend = RedisCacheBackend::connect(&redis.url).await?;
        Ok(Self::from_backend(config, backend))
    }

    #[cfg(not(feature = "cache-redis"))]
    async fn from_redis_config(_config: CacheConfig) -> CacheResult<Self> {
        Err(CacheError::InvalidConfig(
            "redis cache backend requires the cache-redis feature".to_string(),
        ))
    }

    #[cfg(feature = "cache-memcached")]
    async fn from_memcached_config(config: CacheConfig) -> CacheResult<Self> {
        let memcached = config.memcached.as_ref().ok_or_else(|| {
            CacheError::InvalidConfig(
                "memcached backend requires cache.memcached.servers".to_string(),
            )
        })?;
        let backend = MemcachedCacheBackend::connect(&memcached.servers).await?;
        Ok(Self::from_backend(config, backend))
    }

    #[cfg(not(feature = "cache-memcached"))]
    async fn from_memcached_config(_config: CacheConfig) -> CacheResult<Self> {
        Err(CacheError::InvalidConfig(
            "memcached cache backend requires the cache-memcached feature".to_string(),
        ))
    }
}

trait CacheBackend: Send + Sync {
    fn get<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<Option<Arc<[u8]>>>>;

    fn set<'ctx>(
        &'ctx self,
        key: &'ctx str,
        value: Arc<[u8]>,
        ttl: CacheTtl,
    ) -> BoxFuture<'ctx, CacheResult<()>>;

    fn delete<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<()>>;
}

#[cfg(feature = "cache")]
#[derive(Clone)]
struct MemoryCacheBackend {
    cache: moka::future::Cache<String, StoredCacheValue>,
}

#[cfg(feature = "cache")]
impl MemoryCacheBackend {
    fn new(max_memory: MemoryBudget) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(max_memory.as_bytes())
            .weigher(|key: &String, value: &StoredCacheValue| {
                key.len()
                    .saturating_add(value.bytes.len())
                    .try_into()
                    .unwrap_or(u32::MAX)
            })
            .build();
        Self { cache }
    }
}

#[cfg(feature = "cache")]
impl CacheBackend for MemoryCacheBackend {
    fn get<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<Option<Arc<[u8]>>>> {
        Box::pin(async move {
            let Some(value) = self.cache.get(key).await else {
                return Ok(None);
            };
            if value.expires_at <= tokio::time::Instant::now() {
                self.cache.invalidate(key).await;
                return Ok(None);
            }
            Ok(Some(Arc::clone(&value.bytes)))
        })
    }

    fn set<'ctx>(
        &'ctx self,
        key: &'ctx str,
        value: Arc<[u8]>,
        ttl: CacheTtl,
    ) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            let expires_at = tokio::time::Instant::now() + ttl.as_duration();
            self.cache
                .insert(
                    key.to_string(),
                    StoredCacheValue {
                        bytes: value,
                        expires_at,
                    },
                )
                .await;
            Ok(())
        })
    }

    fn delete<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            self.cache.invalidate(key).await;
            Ok(())
        })
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone)]
struct StoredCacheValue {
    bytes: Arc<[u8]>,
    expires_at: tokio::time::Instant,
}

#[cfg(feature = "cache-redis")]
#[derive(Clone)]
struct RedisCacheBackend {
    connection: redis::aio::ConnectionManager,
}

#[cfg(feature = "cache-redis")]
impl RedisCacheBackend {
    async fn connect(url: &str) -> CacheResult<Self> {
        let client = redis::Client::open(url)
            .map_err(|error| CacheError::Backend(format!("redis client error: {error}")))?;
        let connection = client
            .get_connection_manager()
            .await
            .map_err(|error| CacheError::Backend(format!("redis connection error: {error}")))?;
        Ok(Self { connection })
    }
}

#[cfg(feature = "cache-redis")]
impl CacheBackend for RedisCacheBackend {
    fn get<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<Option<Arc<[u8]>>>> {
        Box::pin(async move {
            use redis::AsyncCommands;

            let mut connection = self.connection.clone();
            let value: Option<Vec<u8>> = connection
                .get(key)
                .await
                .map_err(|error| CacheError::Backend(format!("redis get failed: {error}")))?;
            Ok(value.map(Arc::from))
        })
    }

    fn set<'ctx>(
        &'ctx self,
        key: &'ctx str,
        value: Arc<[u8]>,
        ttl: CacheTtl,
    ) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            use redis::AsyncCommands;

            let mut connection = self.connection.clone();
            let seconds = ttl.as_duration().as_secs().max(1);
            connection
                .set_ex::<_, _, ()>(key, value.as_ref(), seconds)
                .await
                .map_err(|error| CacheError::Backend(format!("redis set failed: {error}")))
        })
    }

    fn delete<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            use redis::AsyncCommands;

            let mut connection = self.connection.clone();
            connection
                .del::<_, ()>(key)
                .await
                .map_err(|error| CacheError::Backend(format!("redis delete failed: {error}")))
        })
    }
}

#[cfg(feature = "cache-memcached")]
struct MemcachedCacheBackend {
    servers: Vec<Arc<Mutex<memcache_async::ascii::Protocol<tokio::net::TcpStream>>>>,
}

#[cfg(feature = "cache-memcached")]
impl MemcachedCacheBackend {
    async fn connect(servers: &[String]) -> CacheResult<Self> {
        if servers.is_empty() {
            return Err(CacheError::InvalidConfig(
                "memcached backend requires at least one server".to_string(),
            ));
        }

        let mut connected = Vec::with_capacity(servers.len());
        for server in servers {
            let stream = tokio::net::TcpStream::connect(server)
                .await
                .map_err(|error| {
                    CacheError::Backend(format!("memcached connect to {server} failed: {error}"))
                })?;
            connected.push(Arc::new(Mutex::new(memcache_async::ascii::Protocol::new(
                stream,
            ))));
        }

        Ok(Self { servers: connected })
    }

    fn server_for_key(
        &self,
        key: &str,
    ) -> Arc<Mutex<memcache_async::ascii::Protocol<tokio::net::TcpStream>>> {
        let server_count = u64::try_from(self.servers.len()).unwrap_or(u64::MAX);
        let index = usize::try_from(stable_hash(key) % server_count).unwrap_or(0);
        Arc::clone(&self.servers[index])
    }
}

#[cfg(feature = "cache-memcached")]
impl CacheBackend for MemcachedCacheBackend {
    fn get<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<Option<Arc<[u8]>>>> {
        Box::pin(async move {
            validate_memcached_key(key)?;
            let server = self.server_for_key(key);
            let result = server.lock().await.get(key).await;
            match result {
                Ok(value) => Ok(Some(Arc::from(value))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(CacheError::Backend(format!(
                    "memcached get failed: {error}"
                ))),
            }
        })
    }

    fn set<'ctx>(
        &'ctx self,
        key: &'ctx str,
        value: Arc<[u8]>,
        ttl: CacheTtl,
    ) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            validate_memcached_key(key)?;
            let expiration = ttl
                .as_duration()
                .as_secs()
                .max(1)
                .try_into()
                .unwrap_or(u32::MAX);
            // The memcached protocol owns one mutable TCP stream per server.
            // Holding the lock across the command keeps request/response frames
            // ordered without exposing connection-pool details to framework users.
            self.server_for_key(key)
                .lock()
                .await
                .set(key, value.as_ref(), expiration)
                .await
                .map_err(|error| CacheError::Backend(format!("memcached set failed: {error}")))
        })
    }

    fn delete<'ctx>(&'ctx self, key: &'ctx str) -> BoxFuture<'ctx, CacheResult<()>> {
        Box::pin(async move {
            validate_memcached_key(key)?;
            self.server_for_key(key)
                .lock()
                .await
                .delete(key)
                .await
                .map_err(|error| CacheError::Backend(format!("memcached delete failed: {error}")))
        })
    }
}

/// Who may share a cached HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseCacheScope {
    /// One cached response is shared by all callers.
    Public,
    /// Cache entries are separated by the request's `Authorization` header.
    PerAuthorization,
}

/// Policy for whole-response caching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseCachePolicy {
    ttl: CacheTtl,
    scope: ResponseCacheScope,
    max_body_bytes: usize,
    vary_headers: Vec<HeaderName>,
}

impl ResponseCachePolicy {
    /// Cache a public response for the provided TTL.
    #[must_use]
    pub fn public(ttl: impl Into<CacheTtl>) -> Self {
        Self {
            ttl: ttl.into(),
            scope: ResponseCacheScope::Public,
            max_body_bytes: DEFAULT_RESPONSE_CACHE_BODY_BYTES,
            vary_headers: Vec::new(),
        }
    }

    /// Cache responses separately for each `Authorization` header value.
    #[must_use]
    pub fn per_authorization(ttl: impl Into<CacheTtl>) -> Self {
        Self {
            ttl: ttl.into(),
            scope: ResponseCacheScope::PerAuthorization,
            max_body_bytes: DEFAULT_RESPONSE_CACHE_BODY_BYTES,
            vary_headers: Vec::new(),
        }
    }

    /// Include a request header in the response-cache key.
    ///
    /// This is useful for low-cardinality headers such as `Accept-Language`.
    /// Avoid high-cardinality or sensitive headers unless they are hashed by a
    /// specific scope such as [`ResponseCacheScope::PerAuthorization`].
    #[must_use]
    pub fn vary_by_header(mut self, header: HeaderName) -> Self {
        self.vary_headers.push(header);
        self
    }

    /// Change the maximum response body size that can be cached.
    #[must_use]
    pub const fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

/// Build a GET route that caches whole responses.
///
/// This keeps route declarations readable:
///
/// ```ignore
/// Router::new().route(
///     "/products",
///     cached_get(cache.clone(), ResponseCachePolicy::public(CacheTtl::seconds(30)), list_products),
/// )
/// ```
pub fn cached_get<HandlerFunction, HandlerArgs, State>(
    cache: ObjectCache,
    policy: ResponseCachePolicy,
    handler: HandlerFunction,
) -> MethodRouter<State>
where
    HandlerFunction: Handler<HandlerArgs, State>,
    HandlerArgs: 'static,
    State: Clone + Send + Sync + 'static,
{
    get(handler).route_layer(from_fn_with_state(
        ResponseCacheState { cache, policy },
        response_cache_middleware,
    ))
}

/// Macro wrapper for the most novice-friendly response-cache route syntax.
///
/// The macro expands to [`cached_get`], so the behavior is the same as the
/// explicit API. It exists to make generated route tables read like intent:
///
/// ```ignore
/// route_cache_get!(
///     cache = services.cache.clone(),
///     ttl = CacheTtl::seconds(30),
///     handler = list_products
/// )
/// ```
#[macro_export]
macro_rules! route_cache_get {
    (cache = $cache:expr, ttl = $ttl:expr, handler = $handler:expr $(,)?) => {
        $crate::cache::cached_get(
            $cache,
            $crate::cache::ResponseCachePolicy::public($ttl),
            $handler,
        )
    };
    (cache = $cache:expr, policy = $policy:expr, handler = $handler:expr $(,)?) => {
        $crate::cache::cached_get($cache, $policy, $handler)
    };
}

#[derive(Clone)]
struct ResponseCacheState {
    cache: ObjectCache,
    policy: ResponseCachePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn response_cache_middleware(
    axum::extract::State(state): axum::extract::State<ResponseCacheState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !is_cacheable_method(request.method()) {
        let mut response = next.run(request).await;
        mark_cache_status(&mut response, "BYPASS");
        return response;
    }

    let key = match response_cache_key(&state.policy, &request) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(error = %error, "Response cache key creation failed");
            let mut response = next.run(request).await;
            mark_cache_status(&mut response, "BYPASS");
            return response;
        }
    };

    match state.cache.get::<CachedHttpResponse>(key.clone()).await {
        Ok(Some(cached)) => return cached_response(cached, "HIT"),
        Ok(None) => {}
        Err(error) => tracing::warn!(error = %error, "Response cache read failed"),
    }

    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let status = parts.status;
    let headers = parts.headers.clone();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::warn!(error = %error, "Response cache could not read response body");
            let mut response = Response::from_parts(parts, Body::empty());
            mark_cache_status(&mut response, "BYPASS");
            return response;
        }
    };

    let mut response = Response::from_parts(parts, Body::from(body_bytes.clone()));
    let stored = should_store_response(status, &headers, body_bytes.len(), &state.policy);
    if stored {
        let cached = CachedHttpResponse {
            status: status.as_u16(),
            headers: cacheable_response_headers(&headers),
            body: body_bytes.to_vec(),
        };
        if let Err(error) = state.cache.set_for(key, state.policy.ttl, &cached).await {
            tracing::warn!(error = %error, "Response cache write failed");
        }
    }
    mark_cache_status(&mut response, if stored { "MISS" } else { "BYPASS" });
    response
}

fn cached_response(cached: CachedHttpResponse, cache_status: &'static str) -> Response {
    let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    let mut response = (status, Body::from(cached.body)).into_response();
    for (name, value) in cached.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    mark_cache_status(&mut response, cache_status);
    response
}

fn response_cache_key(
    policy: &ResponseCachePolicy,
    request: &axum::extract::Request,
) -> CacheResult<CacheKey> {
    let mut key = CacheKey::new("response")
        .part(request.method().as_str())
        .part(
            request
                .uri()
                .path_and_query()
                .map_or_else(|| request.uri().path(), http::uri::PathAndQuery::as_str),
        );

    match policy.scope {
        ResponseCacheScope::Public => {
            key = key.part("public");
        }
        ResponseCacheScope::PerAuthorization => {
            let Some(value) = request.headers().get(http::header::AUTHORIZATION) else {
                return Err(CacheError::InvalidKey(
                    "per-authorization response caching requires Authorization".to_string(),
                ));
            };
            key = key.part(stable_hash(value.as_bytes()));
        }
    }

    for header in &policy.vary_headers {
        let value = request
            .headers()
            .get(header)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        key = key.part(header.as_str()).part(value);
    }

    Ok(key)
}

fn is_cacheable_method(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

fn should_store_response(
    status: StatusCode,
    headers: &http::HeaderMap,
    body_size: usize,
    policy: &ResponseCachePolicy,
) -> bool {
    status.is_success()
        && body_size <= policy.max_body_bytes
        && !headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("no-store"))
        && !headers.contains_key(http::header::SET_COOKIE)
}

fn cacheable_response_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _value)| is_cacheable_response_header(name))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn is_cacheable_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "set-cookie"
    )
}

fn mark_cache_status(response: &mut Response, status: &'static str) {
    response
        .headers_mut()
        .insert("x-cache", HeaderValue::from_static(status));
}

fn validate_backend_key(key: &str) -> CacheResult<()> {
    validate_memcached_key(key)
}

fn validate_memcached_key(key: &str) -> CacheResult<()> {
    if key.is_empty() {
        return Err(CacheError::InvalidKey(
            "cache key cannot be empty".to_string(),
        ));
    }
    if key.len() > MAX_MEMCACHED_KEY_BYTES {
        return Err(CacheError::InvalidKey(format!(
            "cache key is {} bytes; maximum supported key length is {} bytes",
            key.len(),
            MAX_MEMCACHED_KEY_BYTES
        )));
    }
    if key
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(CacheError::InvalidKey(
            "cache key cannot contain whitespace or control characters".to_string(),
        ));
    }
    Ok(())
}

fn encode_key_part(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'A' + (value - 10)),
        _ => '0',
    }
}

fn stable_hash(value: impl AsRef<[u8]>) -> u64 {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let mut hash = FNV_OFFSET;
    for byte in value.as_ref() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

struct DurationText(Duration);

impl<'de> Deserialize<'de> for DurationText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = DurationText;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a duration in seconds or a string such as '30s', '5m', '1h'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(DurationText(Duration::from_secs(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_duration_text(value)
                    .map(DurationText)
                    .map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

struct MemoryBudgetText(u64);

impl<'de> Deserialize<'de> for MemoryBudgetText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = MemoryBudgetText;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte count or memory string such as '128 MiB'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(MemoryBudgetText(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_memory_budget(value)
                    .map(MemoryBudgetText)
                    .map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

fn parse_duration_text(value: &str) -> Result<Duration, String> {
    let trimmed = value.trim();
    let (number, unit) = split_number_and_unit(trimmed)?;
    let amount = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration amount '{number}'"))?;
    let seconds = match unit.to_ascii_lowercase().as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => amount,
        "m" | "min" | "mins" | "minute" | "minutes" => amount.saturating_mul(60),
        "h" | "hr" | "hrs" | "hour" | "hours" => amount.saturating_mul(60 * 60),
        other => return Err(format!("unsupported duration unit '{other}'")),
    };
    Ok(Duration::from_secs(seconds))
}

fn parse_memory_budget(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let (number, unit) = split_number_and_unit(trimmed)?;
    let amount = number
        .parse::<u64>()
        .map_err(|_| format!("invalid memory amount '{number}'"))?;
    let multiplier = match unit.to_ascii_lowercase().replace(' ', "").as_str() {
        "" | "b" | "byte" | "bytes" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        other => return Err(format!("unsupported memory unit '{other}'")),
    };
    Ok(amount.saturating_mul(multiplier))
}

fn split_number_and_unit(value: &str) -> Result<(&str, &str), String> {
    let split_at = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split_at);
    if number.is_empty() {
        return Err(format!("missing numeric value in '{value}'"));
    }
    Ok((number, unit.trim()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::routing::post;
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};
    use tower::ServiceExt;

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct CachedThing {
        name: String,
    }

    async fn body_text(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("response body should be UTF-8")
    }

    #[tokio::test]
    async fn object_cache_stores_typed_values() {
        let cache = ObjectCache::memory();
        let key = CacheKey::new("things").part("one");

        cache
            .set_for(
                key.clone(),
                CacheTtl::seconds(30),
                &CachedThing {
                    name: "cached".to_string(),
                },
            )
            .await
            .expect("set cache value");

        let value = cache
            .get::<CachedThing>(key)
            .await
            .expect("read cache")
            .expect("cached value");
        assert_eq!(
            value,
            CachedThing {
                name: "cached".to_string()
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn object_cache_expires_memory_values() {
        let cache = ObjectCache::memory();
        let key = CacheKey::new("things").part("short");
        cache
            .set_for(key.clone(), CacheTtl::seconds(5), &"fresh")
            .await
            .expect("set cache value");

        assert_eq!(
            cache
                .get::<String>(key.clone())
                .await
                .expect("read before expiry"),
            Some("fresh".to_string())
        );

        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(
            cache.get::<String>(key).await.expect("read after expiry"),
            None
        );
    }

    #[tokio::test]
    async fn get_or_load_coalesces_concurrent_misses() {
        let cache = ObjectCache::memory();
        let load_count = Arc::new(AtomicUsize::new(0));
        let key = CacheKey::new("coalesce").part("one");

        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let cache = cache.clone();
                let key = key.clone();
                let load_count = Arc::clone(&load_count);
                tokio::spawn(async move {
                    cache
                        .get_or_load(key, CacheTtl::seconds(30), async move || {
                            load_count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Ok::<_, BoxError>("loaded".to_string())
                        })
                        .await
                        .expect("load value")
                })
            })
            .collect();

        let values = futures_util::future::join_all(tasks).await;
        for value in values {
            assert_eq!(value.expect("join task"), "loaded");
        }
        assert_eq!(load_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_or_load_releases_waiters_when_store_fails() {
        struct FailingFirstSetBackend {
            first_set: std::sync::atomic::AtomicBool,
        }

        impl CacheBackend for FailingFirstSetBackend {
            fn get<'ctx>(
                &'ctx self,
                _key: &'ctx str,
            ) -> BoxFuture<'ctx, CacheResult<Option<Arc<[u8]>>>> {
                Box::pin(async { Ok(None) })
            }

            fn set<'ctx>(
                &'ctx self,
                _key: &'ctx str,
                _value: Arc<[u8]>,
                _ttl: CacheTtl,
            ) -> BoxFuture<'ctx, CacheResult<()>> {
                Box::pin(async move {
                    if self.first_set.swap(false, Ordering::SeqCst) {
                        Err(CacheError::Backend("intentional set failure".to_string()))
                    } else {
                        Ok(())
                    }
                })
            }

            fn delete<'ctx>(&'ctx self, _key: &'ctx str) -> BoxFuture<'ctx, CacheResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let cache = ObjectCache::from_backend(
            CacheConfig::memory(),
            FailingFirstSetBackend {
                first_set: std::sync::atomic::AtomicBool::new(true),
            },
        );
        let key = CacheKey::new("failure").part("store");

        let first = cache
            .get_or_load(key.clone(), CacheTtl::seconds(30), async || {
                Ok::<_, BoxError>("first".to_string())
            })
            .await;
        assert!(matches!(first, Err(CacheError::Backend(_))));

        let second = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_load(key, CacheTtl::seconds(30), async || {
                Ok::<_, BoxError>("second".to_string())
            }),
        )
        .await
        .expect("second load should not wait forever after failed store")
        .expect("second load should succeed");
        assert_eq!(second, "second");
    }

    #[test]
    fn cache_key_encodes_parts_unambiguously() {
        let key = CacheKey::new("products").part("a:b").part("white space");
        assert_eq!(key.as_str(), "products:a%3Ab:white%20space");
    }

    #[test]
    fn cache_config_parses_friendly_units() {
        let config: CacheConfig = toml::from_str(
            r#"
            backend = "memory"
            algorithm = "tiny-lfu"
            max_memory = "64 MiB"
            default_ttl = "5m"
            namespace = "catalog"
            single_flight = true
            "#,
        )
        .expect("parse cache config");

        assert_eq!(config.max_memory.as_bytes(), 64 * 1024 * 1024);
        assert_eq!(config.default_ttl.as_duration(), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn response_cache_caches_successful_gets() {
        let cache = ObjectCache::memory();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let app = Router::new().route(
            "/cached",
            cached_get(
                cache,
                ResponseCachePolicy::public(CacheTtl::seconds(30)),
                move || {
                    let handler_calls = Arc::clone(&handler_calls);
                    async move {
                        let count = handler_calls.fetch_add(1, Ordering::SeqCst) + 1;
                        format!("call-{count}")
                    }
                },
            ),
        );

        let first = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/cached")
                    .body(Body::empty())
                    .expect("build first request"),
            )
            .await
            .expect("first response");
        assert_eq!(
            first.headers().get("x-cache"),
            Some(&HeaderValue::from_static("MISS"))
        );
        assert_eq!(body_text(first).await, "call-1");

        let second = app
            .oneshot(
                http::Request::builder()
                    .uri("/cached")
                    .body(Body::empty())
                    .expect("build second request"),
            )
            .await
            .expect("second response");
        assert_eq!(
            second.headers().get("x-cache"),
            Some(&HeaderValue::from_static("HIT"))
        );
        assert_eq!(body_text(second).await, "call-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn response_cache_bypasses_non_get_requests() {
        let cache = ObjectCache::memory();
        let policy = ResponseCachePolicy::public(CacheTtl::seconds(30));
        let app = Router::new().route(
            "/submit",
            post(async || "created").route_layer(from_fn_with_state(
                ResponseCacheState { cache, policy },
                response_cache_middleware,
            )),
        );

        let response = app
            .oneshot(
                http::Request::builder()
                    .method("POST")
                    .uri("/submit")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.headers().get("x-cache"),
            Some(&HeaderValue::from_static("BYPASS"))
        );
        assert_eq!(body_text(response).await, "created");
    }
}
