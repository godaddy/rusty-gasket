//! Database configuration and backend detection.
//!
//! Supports `PostgreSQL` and `MySQL` via `SQLx`'s `Any` driver. The backend
//! can be specified explicitly or auto-detected from the connection URL
//! scheme (`postgres://`, `postgresql://`, `mysql://`).

use serde::{Deserialize, Serialize};

/// Which database backend to use.
///
/// `Auto` (the default) detects the backend from the URL scheme:
/// `postgresql://` or `postgres://` → Postgres, `mysql://` → `MySQL`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    /// Auto-detect from the connection URL scheme.
    #[default]
    Auto,
    /// Force `PostgreSQL` backend regardless of URL scheme.
    Postgres,
    /// Force `MySQL` backend regardless of URL scheme.
    #[serde(alias = "mysql")]
    MySql,
}

impl DatabaseBackend {
    /// Resolve the backend from a connection URL when set to `Auto`.
    ///
    /// # Errors
    /// Returns [`ConfigError::UnknownUrlScheme`] when this is `Auto` and the
    /// URL scheme does not match a supported backend. `Postgres` and `MySql`
    /// are infallible.
    pub fn resolve(self, url: &str) -> Result<ResolvedBackend, ConfigError> {
        match self {
            Self::Postgres => Ok(ResolvedBackend::Postgres),
            Self::MySql => Ok(ResolvedBackend::MySql),
            Self::Auto => {
                let lower = url.to_ascii_lowercase();
                if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
                    Ok(ResolvedBackend::Postgres)
                } else if lower.starts_with("mysql://") {
                    Ok(ResolvedBackend::MySql)
                } else {
                    let scheme = url.split("://").next().unwrap_or("unknown");
                    Err(ConfigError::UnknownUrlScheme(format!("{scheme}://...")))
                }
            }
        }
    }
}

/// A backend that has been resolved from `Auto` to a concrete type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedBackend {
    /// `PostgreSQL` backend.
    Postgres,
    /// `MySQL` backend.
    MySql,
}

impl std::fmt::Display for ResolvedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgres"),
            Self::MySql => write!(f, "mysql"),
        }
    }
}

/// Database connection pool configuration.
///
/// Can be loaded from the `"database"` section of `AppConfig`,
/// or constructed from environment variables via `from_env()`.
///
/// `Debug` redacts userinfo from `url` so that accidental log statements
/// (`tracing::debug!(?config, ...)`, panic messages, `dbg!`) cannot leak
/// the password. Reach the unredacted URL through `cfg.url` when it is
/// needed for connection setup.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DatabaseConfig {
    /// Connection URL (e.g., `postgres://user:pass@host/db` or `mysql://user:pass@host/db`).
    #[serde(skip_serializing)]
    pub url: String,

    /// Which backend to use. Default: auto-detect from URL scheme.
    #[serde(default)]
    pub backend: DatabaseBackend,

    /// Maximum number of connections in the pool.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of idle connections to maintain.
    #[serde(default)]
    pub min_connections: u32,

    /// Whether to run migrations on startup. The `DatabasePlugin` checks
    /// this flag and runs `SQLx` migrations from `./migrations/` when true.
    #[serde(default = "default_true")]
    pub run_migrations: bool,

    /// Maximum time to wait for an available connection before returning
    /// an error. Without this the transaction middleware would block
    /// indefinitely under pool exhaustion and never surface a 503.
    #[serde(default = "default_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
}

const fn default_max_connections() -> u32 {
    32
}

const fn default_acquire_timeout_secs() -> u64 {
    5
}

const fn default_true() -> bool {
    true
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            backend: DatabaseBackend::Auto,
            max_connections: default_max_connections(),
            min_connections: 0,
            run_migrations: true,
            acquire_timeout_secs: default_acquire_timeout_secs(),
        }
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &redact_url_userinfo(&self.url))
            .field("backend", &self.backend)
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("run_migrations", &self.run_migrations)
            .finish()
    }
}

/// Replace any `user:password@` in a connection URL with `***@`.
///
/// Operates on the byte position of the first `://` and the first `@`
/// after it. Returns the input unchanged when no userinfo is present
/// or when the URL is not parseable as `scheme://...`.
fn redact_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = scheme_end + "://".len();
    let rest = &url[after_scheme..];
    // userinfo ends at the first `@`, but only if that `@` is before the
    // first `/` (otherwise the `@` is inside the path).
    let path_start = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..path_start];
    match authority.find('@') {
        Some(at) => {
            let mut redacted = String::with_capacity(url.len());
            redacted.push_str(&url[..after_scheme]);
            redacted.push_str("***");
            redacted.push_str(&rest[at..]);
            redacted
        }
        None => url.to_string(),
    }
}

impl DatabaseConfig {
    /// Load configuration from environment variables.
    ///
    /// - `DATABASE_URL` — connection string (required)
    /// - `DB_BACKEND` — "postgres" or "mysql" (default: auto-detect from URL)
    /// - `DB_MAX_CONNECTIONS` — pool size (default: 32)
    /// - `DB_MIN_CONNECTIONS` — minimum idle connections (default: 0)
    /// - `DB_RUN_MIGRATIONS` — run migrations on startup (default: true)
    /// - `DB_ACQUIRE_TIMEOUT_SECS` — max wait for a free connection
    ///   before returning an error (default: 5 seconds)
    ///
    /// # Errors
    /// Returns [`ConfigError::MissingEnvVar`] if `DATABASE_URL` is unset, or
    /// [`ConfigError::InvalidBackend`] if `DB_BACKEND` is set to an
    /// unrecognized value.
    pub fn from_env() -> Result<Self, ConfigError> {
        let url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingEnvVar("DATABASE_URL".to_string()))?;

        let backend = match std::env::var("DB_BACKEND") {
            Ok(v) => match v.to_lowercase().as_str() {
                "postgres" | "postgresql" => DatabaseBackend::Postgres,
                "mysql" => DatabaseBackend::MySql,
                "auto" => DatabaseBackend::Auto,
                other => {
                    return Err(ConfigError::InvalidBackend(other.to_string()));
                }
            },
            Err(_) => DatabaseBackend::Auto,
        };

        let max_connections = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(default_max_connections);

        let min_connections = std::env::var("DB_MIN_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let run_migrations =
            std::env::var("DB_RUN_MIGRATIONS").map_or(true, |v| v != "false" && v != "0");

        let acquire_timeout_secs = std::env::var("DB_ACQUIRE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(default_acquire_timeout_secs);

        Ok(Self {
            url,
            backend,
            max_connections,
            min_connections,
            run_migrations,
            acquire_timeout_secs,
        })
    }
}

/// Errors that can occur during database configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A required environment variable (e.g., `DATABASE_URL`) was not set.
    #[error("Required environment variable not set: {0}")]
    MissingEnvVar(String),

    /// The connection URL scheme could not be matched to a known backend.
    /// The URL is sanitized to prevent credential exposure in logs.
    #[error("Failed to determine database backend from URL scheme: {0}")]
    UnknownUrlScheme(String),

    /// An unrecognized value was provided for `DB_BACKEND`.
    #[error("Unknown database backend: '{0}' (expected: postgres, mysql, or auto)")]
    InvalidBackend(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detect_postgres_url() {
        let result = DatabaseBackend::Auto.resolve("postgres://localhost/mydb");
        assert_eq!(result.expect("resolve"), ResolvedBackend::Postgres);
    }

    #[test]
    fn auto_detect_postgresql_url() {
        let result = DatabaseBackend::Auto.resolve("postgresql://localhost/mydb");
        assert_eq!(result.expect("resolve"), ResolvedBackend::Postgres);
    }

    #[test]
    fn auto_detect_mysql_url() {
        let result = DatabaseBackend::Auto.resolve("mysql://localhost/mydb");
        assert_eq!(result.expect("resolve"), ResolvedBackend::MySql);
    }

    #[test]
    fn auto_detect_unknown_url_is_error() {
        let err = DatabaseBackend::Auto
            .resolve("sqlite://local.db")
            .expect_err("sqlite is not a supported backend");
        assert!(
            matches!(err, ConfigError::UnknownUrlScheme(_)),
            "expected ConfigError::UnknownUrlScheme, got {err:?}"
        );
    }

    #[test]
    fn explicit_backend_ignores_url() {
        let result = DatabaseBackend::Postgres.resolve("mysql://localhost/mydb");
        assert_eq!(result.expect("resolve"), ResolvedBackend::Postgres);
    }

    #[test]
    fn default_backend_is_auto() {
        assert_eq!(DatabaseBackend::default(), DatabaseBackend::Auto);
    }

    #[test]
    fn resolved_backend_display() {
        assert_eq!(ResolvedBackend::Postgres.to_string(), "postgres");
        assert_eq!(ResolvedBackend::MySql.to_string(), "mysql");
    }

    #[test]
    fn debug_redacts_password() {
        let cfg = DatabaseConfig {
            url: "postgres://alice:supersecret@db.internal:5432/app".to_string(),
            ..DatabaseConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("supersecret"),
            "password leaked in Debug: {dbg}"
        );
        assert!(!dbg.contains("alice"), "username leaked in Debug: {dbg}");
        assert!(dbg.contains("db.internal:5432/app"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn debug_passes_through_url_without_userinfo() {
        let cfg = DatabaseConfig {
            url: "postgres://db.internal:5432/app".to_string(),
            ..DatabaseConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("db.internal:5432/app"));
        assert!(!dbg.contains("***"));
    }

    #[test]
    fn debug_handles_empty_url() {
        let cfg = DatabaseConfig::default();
        // Round-trips through Debug without panicking.
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("DatabaseConfig"));
    }

    #[test]
    fn redact_url_userinfo_preserves_non_url_strings() {
        assert_eq!(redact_url_userinfo(""), "");
        assert_eq!(redact_url_userinfo("not-a-url"), "not-a-url");
    }

    #[test]
    fn redact_url_userinfo_does_not_touch_at_in_path() {
        // "@" only inside the path component must not be treated as userinfo.
        let url = "postgres://host:5432/db/path@with-at";
        assert_eq!(redact_url_userinfo(url), url);
    }
}
