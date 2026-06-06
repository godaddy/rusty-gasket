//! Application configuration system.
//!
//! Supports TOML and YAML config files with environment-based overrides,
//! env var resolution (`GASKET_ENV`), and a pluggable secrets backend.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::BoxError;

/// The deployment environment the application is running in.
/// Used for environment-specific config overrides and log formatting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Environment {
    #[default]
    Local,
    #[serde(rename = "dev-private", alias = "devprivate")]
    DevPrivate,
    #[serde(alias = "dev")]
    Development,
    Test,
    Staging,
    #[serde(alias = "prod")]
    Production,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::DevPrivate => write!(f, "dev-private"),
            Self::Development => write!(f, "development"),
            Self::Test => write!(f, "test"),
            Self::Staging => write!(f, "staging"),
            Self::Production => write!(f, "production"),
        }
    }
}

/// HTTP server bind configuration (host and port).
///
/// Defaults are read from `HOST` and `PORT` environment variables at
/// **parse time** (when `serde` deserializes the config). If the env
/// vars change after the config is parsed, the change is not reflected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Bind address for the HTTP server (default: `HOST` env var or `0.0.0.0`).
    #[serde(default = "default_host")]
    pub host: String,
    /// Bind port for the HTTP server (default: `PORT` env var or `8443`).
    #[serde(default = "default_port")]
    pub port: u16,
    /// When set (and the `tls` feature is enabled), the server serves over TLS
    /// (rustls) instead of plaintext. Never (de)serialized — key material is
    /// supplied programmatically by the caller, not via the config file.
    #[cfg(feature = "tls")]
    #[serde(skip)]
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
}

impl ServerConfig {
    /// Create a `ServerConfig` for the given host and port.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// Serve over TLS using the given cert/key material (requires the `tls`
    /// feature). Replaces the default plaintext serve path.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

/// PEM-encoded TLS material for serving over rustls (requires the `tls`
/// feature). Construct with [`TlsConfig::from_pem`] (bring your own cert/key) or
/// [`TlsConfig::self_signed`] (mint one on the spot — handy for a backend hop
/// whose peer doesn't verify the certificate, e.g. a load-balancer→task leg).
#[cfg(feature = "tls")]
#[derive(Clone)]
#[non_exhaustive]
pub struct TlsConfig {
    /// PEM-encoded certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded PKCS#8 / SEC1 private key.
    pub key_pem: Vec<u8>,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Build from PEM-encoded certificate-chain and private-key bytes.
    #[must_use]
    pub fn from_pem(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self { cert_pem, key_pem }
    }

    /// Mint a fresh **self-signed** certificate covering `sans` (DNS names and/or
    /// IP strings) and build a `TlsConfig` from it.
    ///
    /// Intended for a backend TLS hop where the peer does **not** verify the
    /// certificate — e.g. a load-balancer that re-encrypts to the task but
    /// doesn't validate the chain (AWS ALB target groups, GoDaddy Katana's
    /// ALB→task leg). Do **not** use it where a client validates the chain. The
    /// private key is generated in-process and never persisted.
    ///
    /// # Errors
    /// Returns an error if key generation or certificate serialization fails.
    pub fn self_signed(sans: Vec<String>) -> Result<Self, BoxError> {
        let issued = rcgen::generate_simple_self_signed(sans)?;
        Ok(Self::from_pem(
            issued.cert.pem().into_bytes(),
            issued.key_pair.serialize_pem().into_bytes(),
        ))
    }
}

// Manual Debug so private key material never lands in logs.
#[cfg(feature = "tls")]
impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

fn default_host() -> String {
    std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string())
}

fn default_port() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443)
}

/// Raw configuration definition loaded from a TOML/YAML file or built in code.
///
/// Call [`resolve()`](Self::resolve) to produce the final [`AppConfig`]
/// after applying environment detection and per-env overrides.
///
/// `Debug` lists the names of the per-environment overrides and extra
/// sections without their values, for the same reason [`AppConfig`]'s
/// `Debug` redacts its sections: the raw maps can carry secrets pulled
/// directly from a config file.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AppConfigDefinition {
    /// Application name (used in logs and health check responses).
    #[serde(default = "default_app_name")]
    pub name: String,
    /// Explicit environment override; if `None`, detected from `GASKET_ENV`.
    #[serde(default)]
    pub env: Option<String>,
    /// HTTP server bind configuration.
    #[serde(default)]
    pub server: ServerConfig,
    /// Per-environment config overrides keyed by environment name.
    #[serde(default)]
    pub environments: HashMap<String, serde_json::Value>,
    /// Additional config sections (database, auth, etc.) captured via `#[serde(flatten)]`.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for AppConfigDefinition {
    fn default() -> Self {
        Self {
            name: default_app_name(),
            env: None,
            server: ServerConfig::default(),
            environments: HashMap::new(),
            extra: HashMap::new(),
        }
    }
}

impl std::fmt::Debug for AppConfigDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut env_names: Vec<&str> = self.environments.keys().map(String::as_str).collect();
        env_names.sort_unstable();
        let mut extra_names: Vec<&str> = self.extra.keys().map(String::as_str).collect();
        extra_names.sort_unstable();
        f.debug_struct("AppConfigDefinition")
            .field("name", &self.name)
            .field("env", &self.env)
            .field("server", &self.server)
            .field("environments", &env_names)
            .field("extra", &extra_names)
            .finish()
    }
}

fn default_app_name() -> String {
    "rusty-gasket-app".to_string()
}

impl AppConfigDefinition {
    /// Create a new definition with the given application name and otherwise
    /// default values. Use the public fields, the `with_*` setters, or
    /// `set_section` to populate the rest.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Override the server bind configuration.
    #[must_use]
    pub fn server(mut self, server: ServerConfig) -> Self {
        self.server = server;
        self
    }

    /// Pin the deployment environment explicitly instead of reading
    /// `GASKET_ENV`.
    #[must_use]
    pub fn env(mut self, env: impl Into<String>) -> Self {
        self.env = Some(env.into());
        self
    }

    /// Parse a config definition from a TOML string.
    ///
    /// # Errors
    /// Returns an error if `contents` is not valid TOML or does not match the
    /// expected schema.
    pub fn from_toml(contents: &str) -> Result<Self, BoxError> {
        Ok(toml::from_str(contents)?)
    }

    /// Parse a config definition from a YAML string.
    ///
    /// # Errors
    /// Returns an error if `contents` is not valid YAML or does not match the
    /// expected schema.
    pub fn from_yaml(contents: &str) -> Result<Self, BoxError> {
        Ok(serde_yaml_ng::from_str(contents)?)
    }

    /// Load a config definition from a file path.
    ///
    /// Detects format from the file extension (`.toml`, `.yaml`, `.yml`).
    /// For unrecognized extensions, tries TOML first, then YAML.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or its contents cannot be
    /// parsed as TOML or YAML. Callers that want to treat a missing file as
    /// "no config" should use [`Self::from_file_optional`].
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BoxError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {e}", path.display()))?;
        Self::parse_with_extension(path, &contents)
    }

    /// Load a config definition from a file path, treating a missing file
    /// as `Ok(None)`. Use this when the caller wants to fall back to
    /// in-code defaults if no config file is present, without resorting
    /// to string-matching the error message.
    ///
    /// # Errors
    /// Returns an error for any I/O failure other than the file not
    /// being present, or for any parse failure.
    pub fn from_file_optional(path: impl AsRef<Path>) -> Result<Option<Self>, BoxError> {
        let path = path.as_ref();
        let contents = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(format!("Failed to read config file '{}': {e}", path.display()).into());
            }
        };
        Self::parse_with_extension(path, &contents).map(Some)
    }

    fn parse_with_extension(path: &Path, contents: &str) -> Result<Self, BoxError> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "toml" => Self::from_toml(contents),
            "yaml" | "yml" => Self::from_yaml(contents),
            _ => Self::from_toml(contents).or_else(|_| Self::from_yaml(contents)),
        }
    }

    /// Resolve the raw definition into a final [`AppConfig`].
    ///
    /// Detects the environment from `GASKET_ENV` (or the explicit `env` field),
    /// applies per-environment overrides, and returns the fully merged config.
    ///
    /// # Errors
    /// Returns an error if `GASKET_ENV` (or the `env` field) names an
    /// environment that is not recognized.
    pub fn resolve(self) -> Result<AppConfig, BoxError> {
        let env_str = std::env::var("GASKET_ENV")
            .ok()
            .or(self.env)
            .unwrap_or_else(|| "local".to_string());

        let env: Environment = serde_json::from_value(serde_json::Value::String(env_str.clone()))
            .map_err(|_| {
                format!(
                    "Unknown environment '{env_str}'. \
                     Valid values: local, dev-private, development, dev, test, staging, production, prod"
                )
            })?;

        let mut sections = self.extra;

        // Deep merge environment-specific overrides into base sections.
        // Try both the raw env string (e.g., "prod") and the canonical
        // name (e.g., "production") so aliases work with overrides.
        let canonical_env = env.to_string();
        let env_overrides = self
            .environments
            .get(&env_str)
            .or_else(|| self.environments.get(&canonical_env));
        if let Some(env_overrides) = env_overrides
            && let Some(obj) = env_overrides.as_object()
        {
            for (key, value) in obj {
                if let Some(existing) = sections.get(key) {
                    sections.insert(key.clone(), deep_merge_json(existing, value));
                } else {
                    sections.insert(key.clone(), value.clone());
                }
            }
        }

        Ok(AppConfig {
            name: self.name,
            env,
            server: self.server,
            sections,
        })
    }
}

/// Resolved application configuration.
///
/// Produced by [`AppConfigDefinition::resolve()`]. Plugin-specific
/// settings are stored in typed sections accessed via `section<T>()`.
///
/// `Debug` lists section names only — section values are not printed
/// because they may contain secrets pulled from raw config files (e.g.
/// `database.url` with embedded credentials). Use `section::<T>()` to
/// read a specific section after parsing.
#[derive(Clone)]
pub struct AppConfig {
    /// Application name (used in logs and health checks).
    pub name: String,
    /// The resolved deployment environment.
    pub env: Environment,
    /// HTTP server bind configuration.
    pub server: ServerConfig,
    /// Plugin-specific typed config sections, keyed by section name.
    sections: HashMap<String, serde_json::Value>,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut section_names: Vec<&str> = self.sections.keys().map(String::as_str).collect();
        section_names.sort_unstable();
        f.debug_struct("AppConfig")
            .field("name", &self.name)
            .field("env", &self.env)
            .field("server", &self.server)
            .field("sections", &section_names)
            .finish()
    }
}

impl AppConfig {
    /// Deserialize a named config section into a typed struct.
    ///
    /// # Errors
    /// Returns an error if the section is missing or cannot be deserialized
    /// into `T`.
    pub fn section<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T, BoxError> {
        let value = self
            .sections
            .get(key)
            .ok_or_else(|| format!("Config section '{key}' not found"))?;
        Ok(serde_json::from_value(value.clone())?)
    }

    /// Deserialize a named config section, returning `T::default()` if the section
    /// is not present. Returns an error if the section exists but cannot be parsed.
    ///
    /// # Errors
    /// Returns an error if the section exists but cannot be deserialized into `T`.
    pub fn section_or_default<T: serde::de::DeserializeOwned + Default>(
        &self,
        key: &str,
    ) -> Result<T, BoxError> {
        match self.sections.get(key) {
            Some(v) => Ok(serde_json::from_value(v.clone())
                .map_err(|e| format!("Config section '{key}' is invalid: {e}"))?),
            None => Ok(T::default()),
        }
    }

    /// Check whether a named config section exists.
    #[must_use]
    pub fn has_section(&self, key: &str) -> bool {
        self.sections.contains_key(key)
    }

    /// Insert or replace a config section (used by plugins during the configure phase).
    pub fn set_section(&mut self, key: &str, value: serde_json::Value) {
        self.sections.insert(key.to_string(), value);
    }
}

/// Recursively merge two JSON values. Object keys in `overlay` override
/// `base`; nested objects are merged recursively rather than replaced wholesale.
fn deep_merge_json(base: &serde_json::Value, overlay: &serde_json::Value) -> serde_json::Value {
    match (base, overlay) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) => {
            let mut merged = base_map.clone();
            for (key, overlay_val) in overlay_map {
                let merged_val = if let Some(base_val) = base_map.get(key) {
                    deep_merge_json(base_val, overlay_val)
                } else {
                    overlay_val.clone()
                };
                merged.insert(key.clone(), merged_val);
            }
            serde_json::Value::Object(merged)
        }
        (_, overlay) => overlay.clone(),
    }
}

/// Trait for retrieving secret values from an external source.
///
/// The default implementation ([`EnvSecretsProvider`]) reads from
/// environment variables. Organization-specific overlays can implement
/// this for AWS Secrets Manager, `HashiCorp` Vault, etc.
pub trait SecretsProvider: Send + Sync + 'static {
    fn get_secret<'ctx>(
        &'ctx self,
        key: &'ctx str,
    ) -> impl Future<Output = Result<Option<SecretValue>, BoxError>> + Send + 'ctx;
}

/// A secret value that wraps `secrecy::SecretString` for zeroize-on-drop.
/// Use `expose()` to read the plaintext — this is explicit to prevent
/// accidental logging of secrets.
pub struct SecretValue {
    inner: secrecy::SecretString,
}

impl SecretValue {
    /// Wrap a plaintext secret. The inner value is zeroized on drop.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: secrecy::SecretString::from(value),
        }
    }

    /// Access the plaintext secret. Named `expose` to make accidental logging obvious in code review.
    #[must_use]
    pub fn expose(&self) -> &str {
        use secrecy::ExposeSecret;
        self.inner.expose_secret()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(***)")
    }
}

/// Default secrets provider that reads from environment variables.
///
/// Converts the key to `UPPER_SNAKE_CASE` (e.g., `"my-secret"` → `MY_SECRET`)
/// and looks it up in the process environment.
#[derive(Debug, Default)]
pub struct EnvSecretsProvider;

impl SecretsProvider for EnvSecretsProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<SecretValue>, BoxError> {
        let env_key = key.to_uppercase().replace('-', "_");
        Ok(std::env::var(&env_key).ok().map(SecretValue::new))
    }
}

/// A named set of strings loaded from config.
///
/// This is useful for policy lists such as allowed OAuth clients,
/// privileged service accounts, rate-limit exemptions, or other simple
/// identifier sets. The type intentionally stores only strings and leaves
/// policy meaning to the wrapper type that owns it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringSet {
    values: HashSet<String>,
}

impl StringSet {
    /// Create an empty string set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a string set from values supplied in code.
    #[must_use]
    pub fn from_values(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    /// Load a string set from a named YAML field.
    ///
    /// A missing file is treated as an empty set. A missing YAML field is
    /// also treated as an empty set, matching the common pattern where an
    /// environment-specific config file may omit a list entirely.
    ///
    /// # Errors
    /// Returns [`StringSetError`] if the file exists but cannot be read,
    /// if the YAML is malformed, if the named field is not a sequence, or
    /// if any item in the sequence is not a string.
    pub fn load_yaml_field_optional(
        path: impl AsRef<Path>,
        field: &'static str,
    ) -> Result<Self, StringSetError> {
        let path = path.as_ref();
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(StringSetError::Io {
                    path: path.to_path_buf(),
                    error,
                });
            }
        };

        let document: serde_json::Value =
            serde_yaml_ng::from_str(&contents).map_err(|error| StringSetError::Parse {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;

        let Some(value) = document.get(field) else {
            return Ok(Self::new());
        };

        let Some(items) = value.as_array() else {
            return Err(StringSetError::InvalidField {
                path: path.to_path_buf(),
                field,
                reason: "expected a YAML sequence of strings",
            });
        };

        let mut values = HashSet::with_capacity(items.len());
        for item in items {
            let Some(value) = item.as_str() else {
                return Err(StringSetError::InvalidField {
                    path: path.to_path_buf(),
                    field,
                    reason: "all sequence entries must be strings",
                });
            };
            values.insert(value.to_string());
        }

        Ok(Self { values })
    }

    /// Merge comma-separated values from an environment variable.
    ///
    /// Empty segments are ignored, so `"a,, b "` produces `a` and `b`.
    #[must_use]
    pub fn with_env_csv(mut self, env_var: &'static str) -> Self {
        if let Ok(raw_values) = std::env::var(env_var) {
            self.extend_csv(&raw_values);
        }
        self
    }

    /// Merge comma-separated values from a string.
    pub fn extend_csv(&mut self, csv: &str) {
        for value in csv
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.values.insert(value.to_string());
        }
    }

    /// Check whether the set contains a value.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.values.contains(value)
    }

    /// Number of values in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterate over the values in arbitrary hash-set order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.values.iter()
    }

    /// Borrow the underlying set for APIs that need a `HashSet`.
    #[must_use]
    pub const fn as_hash_set(&self) -> &HashSet<String> {
        &self.values
    }

    /// Consume the wrapper and return the underlying `HashSet`.
    #[must_use]
    pub fn into_hash_set(self) -> HashSet<String> {
        self.values
    }
}

/// Error returned while loading a [`StringSet`] from YAML.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StringSetError {
    /// The file existed but could not be read.
    #[error("Failed to read string-set file '{}': {error}", path.display())]
    Io {
        /// Path to the YAML file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        error: std::io::Error,
    },
    /// The file contents were not valid YAML.
    #[error("Failed to parse string-set file '{}': {reason}", path.display())]
    Parse {
        /// Path to the YAML file.
        path: PathBuf,
        /// Parser error text.
        reason: String,
    },
    /// The named YAML field existed but did not have the expected shape.
    #[error("Invalid string-set field '{field}' in '{}': {reason}", path.display())]
    InvalidField {
        /// Path to the YAML file.
        path: PathBuf,
        /// YAML field name that should contain the string list.
        field: &'static str,
        /// Human-readable validation failure.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tls")]
    #[test]
    fn self_signed_produces_pem_and_sets_tls() {
        let tls = TlsConfig::self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("mint self-signed cert");
        let cert = String::from_utf8(tls.cert_pem.clone()).expect("utf8 cert");
        let key = String::from_utf8(tls.key_pem.clone()).expect("utf8 key");
        assert!(cert.contains("BEGIN CERTIFICATE"), "cert PEM expected");
        assert!(key.contains("PRIVATE KEY"), "key PEM expected");
        // Usable as a server's TLS config; Debug must not leak the key.
        let server = ServerConfig::default().with_tls(tls);
        assert!(server.tls.is_some());
        assert!(!format!("{server:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn environment_parsing() {
        let env: Environment =
            serde_json::from_value(serde_json::Value::String("production".to_string()))
                .expect("parse");
        assert_eq!(env, Environment::Production);

        let env: Environment =
            serde_json::from_value(serde_json::Value::String("prod".to_string()))
                .expect("parse alias");
        assert_eq!(env, Environment::Production);

        let env: Environment =
            serde_json::from_value(serde_json::Value::String("dev-private".to_string()))
                .expect("parse alias");
        assert_eq!(env, Environment::DevPrivate);
    }

    #[test]
    fn environment_serde_round_trip_matches_display() {
        // Every variant must round-trip through serde and match its Display
        // form, so config files written by serde can be read back and the
        // display string can be used as a config key.
        for env in [
            Environment::Local,
            Environment::DevPrivate,
            Environment::Development,
            Environment::Test,
            Environment::Staging,
            Environment::Production,
        ] {
            let value = serde_json::to_value(env).expect("serialize");
            let s = value.as_str().expect("string");
            assert_eq!(s, env.to_string(), "serde and Display disagree for {env:?}");
            let back: Environment = serde_json::from_value(value).expect("round-trip");
            assert_eq!(back, env);
        }
    }

    #[test]
    fn config_from_toml() {
        let toml_str = r#"
            name = "my-api"
            env = "test"

            [server]
            host = "127.0.0.1"
            port = 3000

            [database]
            url = "postgres://localhost/mydb"
        "#;

        let def = AppConfigDefinition::from_toml(toml_str).expect("parse toml");
        assert_eq!(def.name, "my-api");

        let config = def.resolve().expect("resolve");
        assert_eq!(config.env, Environment::Test);
        assert_eq!(config.server.port, 3000);
        assert!(config.has_section("database"));
    }

    #[test]
    fn config_env_overrides_replace_base_when_resolved_env_matches() {
        // Pin env in the TOML so this test does not depend on process-wide
        // GASKET_ENV state — this test runs without the env-mutation lock.
        let toml_str = r#"
            name = "my-api"
            env = "production"

            [database]
            url = "postgres://localhost/dev"
            max_connections = 10

            [environments.production.database]
            url = "postgres://prod-host/prod"
        "#;

        let def = AppConfigDefinition::from_toml(toml_str).expect("parse");
        let config = def.resolve().expect("resolve");
        assert_eq!(config.env, Environment::Production);

        // The override replaced url, but max_connections (only in base) is preserved
        // by deep_merge — proving merge semantics, not just a wholesale override.
        let db: serde_json::Value = config.section("database").expect("database section");
        assert_eq!(db["url"], "postgres://prod-host/prod");
        assert_eq!(db["max_connections"], 10);
    }

    #[test]
    fn config_env_overrides_skipped_when_env_does_not_match() {
        let toml_str = r#"
            name = "my-api"
            env = "local"

            [database]
            url = "postgres://localhost/dev"

            [environments.production.database]
            url = "postgres://prod-host/prod"
        "#;

        let def = AppConfigDefinition::from_toml(toml_str).expect("parse");
        let config = def.resolve().expect("resolve");
        assert_eq!(config.env, Environment::Local);

        let db: serde_json::Value = config.section("database").expect("database section");
        assert_eq!(db["url"], "postgres://localhost/dev");
    }

    #[test]
    fn app_config_definition_debug_omits_section_values() {
        // The pre-resolution definition stores raw `extra` and
        // `environments` maps that can hold the same secrets the
        // post-resolution AppConfig redacts. Debug must list only the
        // key names so dbg!(&definition) is safe during plugin authoring.
        let toml_str = r#"
            name = "my-api"
            env = "local"

            [database]
            url = "postgres://admin:another_secret_456@db.internal/app"

            [environments.production.database]
            url = "postgres://prod-admin:prod_secret_789@prod.internal/app"
        "#;

        let def = AppConfigDefinition::from_toml(toml_str).expect("parse");
        let debug = format!("{def:?}");
        assert!(
            !debug.contains("another_secret_456"),
            "AppConfigDefinition Debug must not print extra values: {debug}"
        );
        assert!(
            !debug.contains("prod_secret_789"),
            "AppConfigDefinition Debug must not print environments values: {debug}"
        );
        assert!(
            debug.contains("database"),
            "section names should still be listed: {debug}"
        );
        assert!(
            debug.contains("production"),
            "environment names should still be listed: {debug}"
        );
    }

    #[test]
    fn app_config_debug_omits_section_values() {
        // Section values can hold secrets pulled directly from raw config
        // (e.g. database URLs with embedded passwords). Debug must not
        // print those values — only the section names — so that accidental
        // `dbg!(&config)` or `tracing::debug!(?config, ...)` cannot leak
        // credentials.
        let toml_str = r#"
            name = "my-api"
            env = "local"

            [database]
            url = "postgres://admin:super_secret_password_123@db.internal/app"
        "#;

        let def = AppConfigDefinition::from_toml(toml_str).expect("parse");
        let config = def.resolve().expect("resolve");

        let debug = format!("{config:?}");
        assert!(
            !debug.contains("super_secret_password_123"),
            "AppConfig Debug must not print section values: {debug}"
        );
        assert!(
            !debug.contains("postgres://"),
            "AppConfig Debug must not print section values: {debug}"
        );
        assert!(
            debug.contains("database"),
            "section names should still be listed: {debug}"
        );
    }

    #[test]
    fn string_set_loads_named_yaml_field() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "clients:\n  - svc-a\n  - svc-b\n").expect("write yaml");

        let set = StringSet::load_yaml_field_optional(&path, "clients").expect("load set");

        assert_eq!(set.len(), 2);
        assert!(set.contains("svc-a"));
        assert!(set.contains("svc-b"));
        assert!(!set.contains("svc-c"));
    }

    #[test]
    fn string_set_missing_file_is_empty() {
        let set = StringSet::load_yaml_field_optional("/does/not/exist.yaml", "clients")
            .expect("missing file");
        assert!(set.is_empty());
    }

    #[test]
    fn string_set_rejects_non_string_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "clients:\n  - svc-a\n  - 42\n").expect("write yaml");

        let result = StringSet::load_yaml_field_optional(&path, "clients");

        assert!(matches!(result, Err(StringSetError::InvalidField { .. })));
    }
}
