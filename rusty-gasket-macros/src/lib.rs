//! Procedural macros for the Rusty Gasket framework.
//!
//! Currently provides `#[derive(ApiError)]` for generating [`ApiError`]
//! trait implementations and `IntoResponse` conversions from annotated
//! enum variants.

use proc_macro::TokenStream;

mod api_error;

/// Derive macro for the `ApiError` trait.
///
/// Each enum variant must be annotated with `#[api_error(code = "...", status = ...)]`.
/// An optional `expose = true/false` controls whether the error message is
/// sent to the client (defaults to `true` for 4xx, `false` for 5xx).
///
/// Also generates an `IntoResponse` implementation that produces
/// standardized JSON error bodies via `error_into_response`.
#[proc_macro_derive(ApiError, attributes(api_error))]
pub fn derive_api_error(input: TokenStream) -> TokenStream {
    api_error::derive(input)
}
