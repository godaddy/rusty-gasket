# Configuration

Environment-aware configuration with TOML/YAML files, deep merge overrides, typed sections, and pluggable secrets.

## Overview

Rusty Gasket's configuration flows through two types:

1. **`AppConfigDefinition`** -- the raw config loaded from a file or built in code. Contains per-environment overrides.
2. **`AppConfig`** -- the resolved config after environment detection and override merging. This is what plugins receive.

## gasket.toml Format

A complete configuration file:

```toml
# Application identity
name = "my-api"

# Explicit environment (optional -- usually set via GASKET_ENV env var)
# env = "local"

# HTTP server
[server]
host = "127.0.0.1"
port = 8080

# Database (read by DatabasePlugin)
[database]
url = "postgres://localhost/mydb"
max_connections = 10
min_connections = 0
run_migrations = true

# Rate limiting (read by rate limit middleware)
[rate_limit]
enabled = true
requests_per_minute = 60
burst_size = 10

# Per-environment overrides
[environments.production.server]
host = "0.0.0.0"
port = 8443

[environments.production.database]
max_connections = 50
min_connections = 5

[environments.production.rate_limit]
requests_per_minute = 120
burst_size = 20
```

YAML is also supported (`gasket.yaml` or `gasket.yml`):

```yaml
name: my-api
server:
  host: "127.0.0.1"
  port: 8080
database:
  url: "postgres://localhost/mydb"
environments:
  production:
    database:
      max_connections: 50
```

## AppConfigDefinition

The raw config definition before resolution:

```rust
pub struct AppConfigDefinition {
    /// Application name (default: "rusty-gasket-app")
    pub name: String,

    /// Explicit environment override. If None, detected from GASKET_ENV.
    pub env: Option<String>,

    /// HTTP server bind configuration
    pub server: ServerConfig,

    /// Per-environment config overrides keyed by environment name
    pub environments: HashMap<String, serde_json::Value>,

    /// Additional config sections (database, auth, etc.)
    /// Captured via #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
```

### Loading

```rust
// From a file (auto-detects format from extension)
let config = AppConfigDefinition::from_file("gasket.toml")?;

// From a TOML string
let config = AppConfigDefinition::from_toml(toml_string)?;

// From a YAML string
let config = AppConfigDefinition::from_yaml(yaml_string)?;

// In code
let config = AppConfigDefinition {
    name: "my-api".into(),
    server: ServerConfig { host: "127.0.0.1".into(), port: 8080 },
    env: None,
    environments: Default::default(),
    extra: Default::default(),
};

// Default (safe fallback)
let config = AppConfigDefinition::default();
```

## Environment Detection

The deployment environment is resolved from three sources (first wins):

1. `GASKET_ENV` environment variable
2. `env` field in the config file
3. Default: `"local"`

Supported environments with aliases:

| Value | Aliases | Environment |
|-------|---------|-------------|
| `local` | -- | `Environment::Local` |
| `dev-private` | -- | `Environment::DevPrivate` |
| `development` | `dev` | `Environment::Development` |
| `test` | -- | `Environment::Test` |
| `staging` | -- | `Environment::Staging` |
| `production` | `prod` | `Environment::Production` |

Unknown values log a warning and fall back to `Environment::Local`.

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Environment {
    #[default]
    Local,
    DevPrivate,
    Development,
    Test,
    Staging,
    Production,
}
```

## Environment-Specific Overrides with Deep Merge

The `[environments]` table provides per-environment config overrides. During `resolve()`, overrides for the detected environment are deep-merged into the base config.

```toml
# Base config (all environments)
[database]
url = "postgres://localhost/dev"
max_connections = 10

# Production overrides
[environments.production.database]
url = "postgres://prod-host/prod"
max_connections = 50
```

Deep merge means nested objects are merged recursively -- a production override for `max_connections` does not erase the `url` from the base config. Non-object values are replaced wholesale.

Both the raw environment string (e.g., `"prod"`) and the canonical name (e.g., `"production"`) are checked, so aliases work with overrides.

## AppConfig (Resolved)

After calling `resolve()`, you get an `AppConfig` with typed accessors:

```rust
pub struct AppConfig {
    pub name: String,              // application name
    pub env: Environment,          // resolved environment
    pub server: ServerConfig,      // bind address and port
    // sections: HashMap<String, serde_json::Value>  (private)
}
```

### Accessing Plugin Sections

```rust
// Deserialize a section into a typed struct (error if missing)
let db_config: DatabaseConfig = config.section("database")?;

// Deserialize with a default fallback (never errors for missing sections)
let rate_config: RateLimitConfig = config.section_or_default("rate_limit");

// Check existence
if config.has_section("database") { /* ... */ }

// Set a section (used by plugins during configure())
config.set_section("my_plugin", serde_json::json!({"enabled": true}));
```

`section_or_default()` returns `T::default()` if the section is missing. If the section exists but fails to deserialize, it logs a warning and returns the default.

## ServerConfig

```rust
pub struct ServerConfig {
    pub host: String,   // default: HOST env var or "0.0.0.0"
    pub port: u16,      // default: PORT env var or 8443
}
```

Defaults are resolved from environment variables at parse time.

## Config Waterfall in Plugins

After `resolve()`, each plugin's `configure()` method receives the config in topological order and can transform it:

```rust
fn configure(&self, mut config: AppConfig) -> AppConfig {
    if !config.has_section("my_plugin") {
        config.set_section("my_plugin", serde_json::json!({
            "timeout_ms": 5000,
            "retries": 3,
        }));
    }
    config
}
```

Then in `prepare()`:

```rust
async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
    let my_config: MyPluginConfig = ctx.config.section("my_plugin")?;
    // Use my_config...
    Ok(())
}
```

## SecretsProvider Trait

For retrieving secrets from external sources:

```rust
pub trait SecretsProvider: Send + Sync + 'static {
    async fn get_secret(&self, key: &str) -> Result<Option<SecretValue>, BoxError>;
}
```

`SecretValue` wraps `secrecy::SecretString` for zeroize-on-drop. Access the plaintext via `.expose()` -- named explicitly to make accidental logging obvious in code review:

```rust
pub struct SecretValue { /* wraps SecretString */ }

impl SecretValue {
    pub fn new(value: String) -> Self;
    pub fn expose(&self) -> &str;  // explicit access
}
```

### Built-in: EnvSecretsProvider

The default provider reads from environment variables. Converts the key to `UPPER_SNAKE_CASE`:

```rust
let provider = EnvSecretsProvider;
// "database-password" -> looks up env var DATABASE_PASSWORD
let secret = provider.get_secret("database-password").await?;
if let Some(s) = secret {
    let password = s.expose();  // plaintext access
}
```

## All Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GASKET_ENV` | `local` | Deployment environment |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8443` | Server listen port |
| `DATABASE_URL` | -- | Database connection URL |
| `DB_BACKEND` | `auto` | Database backend (`postgres`, `mysql`, `auto`) |
| `DB_MAX_CONNECTIONS` | `10` | Connection pool size |
| `DB_MIN_CONNECTIONS` | `0` | Minimum idle connections |
| `DB_RUN_MIGRATIONS` | `true` | Run migrations on startup |
| `RUST_LOG` | `info` | Log level filter (tracing `EnvFilter`) |
| `RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `60` | Sustained request rate per key |
| `RATE_LIMIT_BURST_SIZE` | `10` | Burst capacity above sustained rate |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | -- | Enables OpenTelemetry when set |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Trace sampling ratio (0.0-1.0) |

## Further Reading

- [Plugin Guide](plugin-guide.md) -- config waterfall in plugins
- [Database](database.md) -- database-specific configuration
- [Observability](observability.md) -- logging and OTEL configuration
