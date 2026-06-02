# Error Handling

Standardized JSON error responses with correlation IDs, the `ApiError` trait, and the `#[derive(ApiError)]` macro.

## Overview

Rusty Gasket provides a structured error system that:

- Produces consistent JSON error responses across all endpoints
- Includes correlation IDs for support debugging
- Hides internal details from clients on 5xx errors
- Logs full error chains server-side
- Reduces boilerplate via a derive macro

## ApiError Trait

The core trait that application error types implement:

```rust
pub trait ApiError: std::error::Error + Send + Sync + 'static {
    /// Machine-readable error code (e.g., "NOT_FOUND", "VALIDATION_ERROR").
    fn error_code(&self) -> &str;

    /// HTTP status code for this error.
    fn status_code(&self) -> StatusCode;

    /// Whether to expose the error message to the client.
    /// Default: true for 4xx, false for 5xx.
    fn expose_details(&self) -> bool {
        self.status_code().is_client_error()
    }

    /// Structured sub-errors (e.g., per-field validation failures).
    fn details(&self) -> Vec<ErrorDetail> {
        Vec::new()
    }
}
```

## #[derive(ApiError)]

The `rusty_gasket_macros` crate provides `#[derive(ApiError)]` for ergonomic implementation. It generates both the `ApiError` trait and `IntoResponse` for axum.

### Basic Usage

```rust
use rusty_gasket::error::ApiError;

#[derive(Debug, thiserror::Error, ApiError)]
pub enum MyError {
    #[error("Item not found: {0}")]
    #[api_error(code = "NOT_FOUND", status = 404)]
    NotFound(String),

    #[error("Invalid input")]
    #[api_error(code = "BAD_REQUEST", status = 400)]
    BadRequest,

    #[error("Database error")]
    #[api_error(code = "INTERNAL_ERROR", status = 500, expose = false)]
    Database(#[source] sqlx::Error),

    #[error("Custom exposed server error")]
    #[api_error(code = "CUSTOM_500", status = 500, expose = true)]
    CustomExposed,

    #[error("Validation failed")]
    #[api_error(code = "VALIDATION", status = 422)]
    Validation { field: String },
}
```

### Attribute Syntax

Each variant requires `#[api_error(...)]` with these parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `code` | Yes | Machine-readable error code string (e.g., `"NOT_FOUND"`) |
| `status` | Yes | HTTP status code as an integer (e.g., `404`) |
| `expose` | No | Override detail exposure. Default: `true` for 4xx, `false` for 5xx |

### Supported Variant Shapes

All enum variant shapes work:

```rust
#[derive(Debug, thiserror::Error, ApiError)]
enum MyError {
    // Unit variant
    #[error("not found")]
    #[api_error(code = "NOT_FOUND", status = 404)]
    NotFound,

    // Tuple variant (positional fields)
    #[error("bad request: {0}")]
    #[api_error(code = "BAD_REQUEST", status = 400)]
    BadRequest(String),

    // Struct variant (named fields)
    #[error("validation failed")]
    #[api_error(code = "VALIDATION", status = 422)]
    Validation { field: String, message: String },

    // With source error
    #[error("database error")]
    #[api_error(code = "INTERNAL", status = 500)]
    Database(#[source] sqlx::Error),
}
```

### Generated Code

For each variant, the macro generates:

1. `error_code()` -- returns the `code` string
2. `status_code()` -- returns the `status` as `StatusCode`
3. `expose_details()` -- returns `true` for 4xx (or explicit `expose = true`), `false` for 5xx
4. `IntoResponse` -- calls `rusty_gasket::error::error_into_response(&self)`

## ErrorResponse JSON Format

All errors produce a standardized JSON body:

```json
{
  "error": "NOT_FOUND",
  "message": "Item not found: widget-42",
  "correlationId": "019734a2-1234-7000-8000-abcdef012345",
  "details": []
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `error` | string | Machine-readable error code |
| `message` | string | Human-readable message (may be redacted for 5xx) |
| `correlationId` | UUID | Links to server-side logs for support |
| `details` | array | Sub-errors (omitted from JSON when empty) |

### ErrorDetail

For structured sub-errors (e.g., validation failures):

```rust
pub struct ErrorDetail {
    pub issue: String,                    // field name or constraint
    pub description: Option<String>,      // longer explanation
}

// Construction
ErrorDetail::new("email");
ErrorDetail::with_description("email", "must be a valid email address");
```

## 4xx vs 5xx Exposure Rules

| Status class | Default behavior |
|-------------|-----------------|
| 4xx (client error) | Message and details exposed to client |
| 5xx (server error) | Message replaced with `"Internal server error (correlation_id: ...)"` |

This prevents accidental leaking of internal details (stack traces, database errors, file paths) to API consumers. Override with `expose = true` on specific 5xx variants when the message is safe for clients.

### Examples

**4xx -- message exposed:**

```json
{
  "error": "NOT_FOUND",
  "message": "Item not found: widget-42",
  "correlationId": "019734a2-..."
}
```

**5xx -- message redacted:**

```json
{
  "error": "INTERNAL_ERROR",
  "message": "Internal server error (correlation_id: 019734a2-...)",
  "correlationId": "019734a2-..."
}
```

## Correlation IDs

Every error response includes a `correlationId` that links to server-side logs. The ID is resolved from:

1. The current request's task-local `CURRENT_REQUEST_ID` (set by the logging middleware)
2. If not available, a fresh UUID v7 is generated

This means errors from background tasks or non-HTTP contexts still get correlation IDs.

### Using Correlation IDs for Debugging

A support request says "I got error correlation_id 019734a2-...". Search your logs:

```bash
# JSON logs
grep "019734a2" logs/app.log

# Structured log query
jq 'select(.correlation_id == "019734a2-...")' logs/app.log
```

The server-side log contains the full error chain:

```
[ERROR] error_code="INTERNAL_ERROR" status=500 correlation_id="019734a2-..."
  error_chain="Database error | caused by: connection refused"
```

## Error Chain Walking

The `full_error_chain()` helper walks the entire `source()` chain for internal logging:

```rust
pub fn full_error_chain(error: &dyn std::error::Error) -> String;
// Returns: "Database error | caused by: connection refused | caused by: ..."
```

This is used automatically by `error_into_response()` when logging 5xx errors.

## Using Errors in Handlers

```rust
use rusty_gasket::error::ApiError;

#[derive(Debug, thiserror::Error, ApiError)]
enum AppError {
    #[error("Item not found: {0}")]
    #[api_error(code = "NOT_FOUND", status = 404)]
    NotFound(String),

    #[error("Database error")]
    #[api_error(code = "INTERNAL_ERROR", status = 500)]
    Database(#[source] sqlx::Error),
}

async fn get_item(Path(id): Path<String>) -> Result<Json<Item>, AppError> {
    let item = find_item(&id).await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound(id))?;
    Ok(Json(item))
}
```

Because `#[derive(ApiError)]` generates `IntoResponse`, the error is automatically converted to the standardized JSON response.

## Framework Errors

Rusty Gasket includes built-in `FrameworkError` for framework-level failures:

```rust
pub enum FrameworkError {
    NotFound,                         // 404
    MethodNotAllowed,                 // 405
    Internal(Box<dyn Error + ...>),   // 500
}
```

These implement `ApiError` and `IntoResponse` so framework-generated errors follow the same JSON format.

## Further Reading

- [Observability](observability.md) -- request IDs and correlation
- [Testing](testing.md) -- testing error responses with `TestResponse::json()`
