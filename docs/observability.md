# Observability

Request ID generation, structured logging, environment-aware formatting, and OpenTelemetry integration.

## Overview

Rusty Gasket's observability system provides:

- **Request ID generation** -- UUID v7 per request, propagated via headers and task-local storage
- **Structured logging** -- JSON in non-local environments, pretty-print locally
- **Per-request tracing spans** -- method, path, status, duration, auth fields
- **Bidirectional middleware communication** -- auth middleware fills in logging fields
- **OpenTelemetry integration** -- OTLP span and metric export (opt-in via `otlp` feature)

## init_tracing()

Initialize the global tracing subscriber based on the deployment environment:

```rust
use rusty_gasket::config::Environment;

// In main()
rusty_gasket::observability::init_tracing(Environment::Local);
```

### Behavior by Environment

| Environment | Format | Features |
|-------------|--------|----------|
| `Local` | Pretty-printed, colored | Human-readable, with targets and thread IDs off |
| All others | JSON (when `json-log` feature enabled) | Machine-parseable structured logs |
| All others (no `json-log`) | Compact text | Minimal overhead |

### Log Level Control

Controlled by the `RUST_LOG` environment variable via tracing's `EnvFilter`:

```bash
RUST_LOG=info cargo run                    # default
RUST_LOG=debug cargo run                   # verbose
RUST_LOG=my_api=debug,rusty_gasket=info    # per-crate levels
```

If `RUST_LOG` is not set, defaults to `info`.

## Security-Tagged JSON

`SecurityJsonFormat` is available for deployments that route auth or authorization events to a SIEM:

```rust
use rusty_gasket::observability::SecurityJsonFormat;

SecurityJsonFormat::new("my_service::auth").init();
```

Events whose tracing target starts with the configured prefix receive a top-level `"tags":["security"]` field. Other JSON log events keep the standard `tracing-subscriber` shape.

## Request ID Generation and Propagation

Each incoming request is assigned a UUID v7 (time-ordered) or inherits one from the `X-Request-ID` header.

### Flow

1. **Logging middleware** extracts `X-Request-ID` from request headers, or generates a UUID v7
2. Stored as `RequestId(String)` in **request extensions** (accessible to other middleware)
3. Stored in **task-local** `CURRENT_REQUEST_ID` (accessible from any async context within the request)
4. Set as database `application_name` by the transaction middleware (for DB log correlation)
5. Echoed back in the **response** `X-Request-ID` header

### Accessing the Request ID

From middleware or handlers (via request extensions):

```rust
use rusty_gasket::observability::RequestId;

async fn my_handler(request: Request) -> impl IntoResponse {
    let request_id = request.extensions()
        .get::<RequestId>()
        .map(|r| r.as_str().to_owned());
    // ...
}
```

From any async context (via task-local):

```rust
use rusty_gasket::observability::current_request_id;

fn log_something() {
    if let Some(id) = current_request_id() {
        tracing::info!(request_id = %id, "something happened");
    }
}
```

The task-local is especially useful in error handlers and utility functions that do not have access to the request object.

### Request ID Validation

Externally-provided request IDs (`X-Request-ID` header) are validated:
- Must not be empty
- Maximum 128 characters
- Allowed characters: alphanumeric, `.`, `_`, `-`

Invalid request IDs are silently replaced with a generated UUID v7.

### Constants

```rust
pub const X_REQUEST_ID: &str = "X-Request-ID";
```

## Structured Logging Fields

The logging middleware creates a root tracing span per request with these fields:

| Field | Source | Description |
|-------|--------|-------------|
| `request_id` | Generated or from header | Unique request identifier |
| `method` | Request | HTTP method (GET, POST, etc.) |
| `path` | Request URI | Raw request path |
| `matched_path` | axum `MatchedPath` | Route template (e.g., `/v1/items/{id}`) |
| `user_agent` | Request header | Client user agent string |
| `env` | `GASKET_ENV` or `DEPLOYMENT_ENV` | Deployment environment |
| `client_id` | Auth middleware | Authenticated client identifier |
| `client_ip` | Auth middleware | Client IP address |
| `user_id` | Auth middleware | Authenticated user subject |
| `auth_method` | Auth middleware | Auth backend name (jwt, api-key, etc.) |
| `auth_result` | Auth middleware | Outcome (authenticated:jwt, anonymous, failed:...) |
| `is_privileged` | Auth middleware | Whether caller has elevated privileges |
| `status` | Response | HTTP status code |
| `duration_ms` | Measured | Request processing time in milliseconds |

Auth fields start as `tracing::field::Empty` and are filled in by the auth middleware via the `LoggingContext` (bidirectional middleware communication).

## LoggingContext (Bidirectional Middleware)

The logging and auth middleware communicate through `LoggingContext`:

```rust
pub struct LoggingContext {
    inner: Arc<Mutex<Option<AuthSummary>>>,
}

pub struct AuthSummary {
    pub client_id: String,
    pub client_ip: String,
    pub user_id: String,
    pub auth_method: String,
    pub auth_result: String,
    pub is_privileged: bool,
}
```

### How it works

1. **Logging middleware** creates a `LoggingContext` and inserts it into request extensions
2. **Auth middleware** reads the `LoggingContext` from extensions and calls `logging_ctx.set(auth_summary)`
3. **After the response**, logging middleware calls `logging_ctx.take()` to read the auth summary
4. Auth fields are recorded in the tracing span

This avoids coupling the two middleware directly -- they communicate through a shared data structure in request extensions.

## OpenTelemetry Integration

When the `otlp` feature is enabled, Rusty Gasket supports exporting traces and metrics to an OTLP-compatible collector (Jaeger, Grafana Tempo, etc.).

### Setup

```rust
use rusty_gasket::otel;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let env = Environment::Production;

    // try_init returns:
    //   None           -- OTEL_EXPORTER_OTLP_ENDPOINT not set (OTEL disabled)
    //   Some(Ok(guard)) -- OTEL initialized successfully
    //   Some(Err(e))   -- initialization failed
    let otel_guard = otel::try_init("my-service", "0.1.0", &env.to_string());

    match &otel_guard {
        Some(Ok(guard)) => {
            // Dual-layer subscriber: fmt (logs) + OTEL (spans/metrics)
            rusty_gasket::observability::init_tracing_with_otel(
                env,
                guard.tracer_provider(),
                "my-service",
            );
        }
        _ => {
            // Standard subscriber (logs only)
            rusty_gasket::observability::init_tracing(env);
        }
    }

    // ... start app ...

    // Guard must live until end of main. When dropped, it flushes
    // pending spans/metrics and shuts down the OTEL providers.
    drop(otel_guard);
    Ok(())
}
```

### OtelGuard

The guard holds the tracer and meter providers alive. When dropped, it:
1. Shuts down the tracer provider (flushes pending spans)
2. Shuts down the meter provider (flushes pending metrics)

```rust
pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl OtelGuard {
    pub fn tracer_provider(&self) -> &SdkTracerProvider;
}
```

### Configuration

OTEL is configured via environment variables (standard OpenTelemetry conventions):

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | -- | Enables OTEL when set (e.g., `http://localhost:4317`) |
| `OTEL_EXPORTER_OTLP_HEADERS` | -- | Custom headers for the OTLP exporter |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Trace sampling ratio (0.0-1.0, default 10%) |

### Sampling

Uses `ParentBased(TraceIdRatioBased)` sampling:
- If the parent span is sampled, the child is too (respects upstream decisions)
- For root spans, samples at the configured ratio (default: 10%)
- Clamped to 0.0-1.0

### Metrics

A periodic metric reader exports metrics every 60 seconds. Metrics are exported via the same OTLP endpoint as traces.

### Filter

The OTEL-enabled subscriber applies a single global filter. By default, noisy low-level crates are silenced:

```
info,h2=off,hyper=off,rustls=off,tonic=off
```

Override with `RUST_LOG`.

### Resource Attributes

Each exported span/metric includes:
- `service.name` -- from `try_init()` parameter
- `service.version` -- from `try_init()` parameter
- `deployment.environment` -- from `try_init()` parameter

## Local Development

For local development with OTEL visualization:

```bash
just up-metrics  # starts Postgres + OTEL collector + Grafana

OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 cargo run -p sample-api
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `json-log` | Yes | JSON structured logging for non-local environments |
| `pretty-log` | No | Colored human-readable logging |
| `otlp` | No | OpenTelemetry OTLP export (traces + metrics) |

## Further Reading

- [Authentication](authentication.md) -- how auth fields are populated
- [Middleware](middleware.md) -- logging middleware slot and ordering
- [Database](database.md) -- request ID correlation in database queries
