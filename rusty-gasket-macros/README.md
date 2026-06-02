# rusty-gasket-macros

Procedural macros for the Rusty Gasket framework. Currently provides `#[derive(ApiError)]` for generating `ApiError` trait implementations and `IntoResponse` conversions from annotated enum variants.

## Usage

```rust
use rusty_gasket::error::ApiError;

#[derive(Debug, thiserror::Error, ApiError)]
enum MyError {
    #[error("thing not found: {0}")]
    #[api_error(code = "NOT_FOUND", status = 404)]
    NotFound(String),

    #[error("bad input")]
    #[api_error(code = "BAD_REQUEST", status = 400)]
    BadRequest,

    #[error("internal failure")]
    #[api_error(code = "INTERNAL", status = 500, expose = false)]
    Internal,

    #[error("custom exposed 500")]
    #[api_error(code = "CUSTOM_500", status = 500, expose = true)]
    CustomExposed,
}
```

## Attributes

Each enum variant must be annotated with `#[api_error(...)]`:

| Attribute | Required | Description |
|-----------|----------|-------------|
| `code` | yes | Machine-readable error code string (e.g., `"NOT_FOUND"`) |
| `status` | yes | HTTP status code (e.g., `404`) |
| `expose` | no | Whether to expose the error message to the client. Defaults to `true` for 4xx, `false` for 5xx |

The derive macro generates:
- An `ApiError` trait implementation with `error_code()`, `status_code()`, and `expose_details()`
- An `IntoResponse` implementation that produces standardized JSON error bodies via `error_into_response()`

## Documentation

See the top-level [README](../../README.md) and the `rusty-gasket` crate's `error` module for the full error handling architecture.
