//! Implementation of the `#[derive(ApiError)]` procedural macro.
//!
//! Parses `#[api_error(...)]` attributes on enum variants and generates
//! the `ApiError` trait implementation (`error_code`, `status_code`,
//! `expose_details`) and, unless the enum carries
//! `#[api_error(skip_into_response)]` at the type level, an
//! `IntoResponse` implementation.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Lit, parse_macro_input};

struct VariantAttrs {
    code: String,
    status: u16,
    expose: Option<bool>,
}

fn parse_api_error_attrs(attrs: &[syn::Attribute]) -> Result<Option<VariantAttrs>, syn::Error> {
    for attr in attrs {
        if !attr.path().is_ident("api_error") {
            continue;
        }

        let mut code = None;
        let mut status = None;
        let mut expose = None;

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("code") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                match lit {
                    Lit::Str(s) => code = Some(s.value()),
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "`code` must be a string literal, e.g. code = \"NOT_FOUND\"",
                        ));
                    }
                }
            } else if meta.path.is_ident("status") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                match lit {
                    Lit::Int(i) => {
                        status = Some(i.base10_parse::<u16>().map_err(|e| meta.error(e))?);
                    }
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "`status` must be an integer literal, e.g. status = 404",
                        ));
                    }
                }
            } else if meta.path.is_ident("expose") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                match lit {
                    Lit::Bool(b) => expose = Some(b.value()),
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "`expose` must be a bool literal, e.g. expose = true",
                        ));
                    }
                }
            } else {
                return Err(
                    meta.error("unknown #[api_error] key; expected one of: code, status, expose")
                );
            }
            Ok(())
        })?;

        if let (Some(code), Some(status)) = (code, status) {
            return Ok(Some(VariantAttrs {
                code,
                status,
                expose,
            }));
        }
    }
    Ok(None)
}

/// Parse a type-level `#[api_error(skip_into_response)]` attribute.
///
/// Callers that hand-roll `IntoResponse` (e.g. to add custom headers)
/// would otherwise hit a duplicate-impl error from the derive. Spelling
/// the opt-out as an attribute keeps the derive's default helpful for
/// the 95% case.
fn parse_skip_into_response(attrs: &[syn::Attribute]) -> Result<bool, syn::Error> {
    let mut skip = false;
    for attr in attrs {
        if !attr.path().is_ident("api_error") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip_into_response") {
                skip = true;
                Ok(())
            } else {
                // Variant-level keys (`code`, `status`, `expose`) are
                // valid further down; ignore them here without error.
                drop(meta.value().and_then(|v| v.parse::<Lit>()));
                Ok(())
            }
        })?;
    }
    Ok(skip)
}

pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let skip_into_response = match parse_skip_into_response(&input.attrs) {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };

    let Data::Enum(data) = &input.data else {
        return syn::Error::new_spanned(&input, "ApiError can only be derived for enums")
            .to_compile_error()
            .into();
    };

    let mut code_arms = Vec::new();
    let mut status_arms = Vec::new();
    let mut expose_arms = Vec::new();

    for variant in &data.variants {
        let ident = &variant.ident;
        let attrs = match parse_api_error_attrs(&variant.attrs) {
            Ok(Some(a)) => a,
            Ok(None) => {
                return syn::Error::new_spanned(
                    variant,
                    "Each variant must have #[api_error(code = \"...\", status = ...)]",
                )
                .to_compile_error()
                .into();
            }
            Err(e) => return e.to_compile_error().into(),
        };

        let code_str = &attrs.code;
        let status_val = attrs.status;

        if !(100..=999).contains(&status_val) {
            return syn::Error::new_spanned(
                variant,
                format!("Invalid HTTP status code {status_val}: must be 100-999"),
            )
            .to_compile_error()
            .into();
        }

        let expose_val = attrs.expose.unwrap_or(status_val < 500);

        let pattern = match &variant.fields {
            Fields::Unit => quote! { #name::#ident },
            Fields::Unnamed(_) => quote! { #name::#ident(..) },
            Fields::Named(_) => quote! { #name::#ident { .. } },
        };

        code_arms.push(quote! { #pattern => #code_str });
        // Emit a `const { ... }` block so the StatusCode construction is
        // evaluated at compile time. `StatusCode::from_u16` is `const`,
        // so an out-of-range value is caught by the const evaluator
        // (with the macro user's literal in the diagnostic) and the
        // generated runtime code has no fallible call site to `expect`
        // on. The 100..=999 check above is redundant with the const
        // eval but is kept so the diagnostic points at the variant
        // before const evaluation runs.
        status_arms.push(quote! {
            #pattern => const {
                match ::axum::http::StatusCode::from_u16(#status_val) {
                    ::core::result::Result::Ok(s) => s,
                    ::core::result::Result::Err(_) => {
                        ::core::panic!("rusty_gasket_macros: invalid HTTP status code")
                    }
                }
            }
        });
        expose_arms.push(quote! { #pattern => #expose_val });
    }

    let into_response_impl = if skip_into_response {
        quote! {}
    } else {
        quote! {
            impl #impl_generics ::axum::response::IntoResponse for #name #ty_generics #where_clause {
                fn into_response(self) -> ::axum::response::Response {
                    ::rusty_gasket::error::error_into_response(&self)
                }
            }
        }
    };

    let expanded = quote! {
        impl #impl_generics ::rusty_gasket::error::ApiError for #name #ty_generics #where_clause {
            fn error_code(&self) -> &str {
                match self {
                    #(#code_arms,)*
                }
            }

            fn status_code(&self) -> ::axum::http::StatusCode {
                match self {
                    #(#status_arms,)*
                }
            }

            fn expose_details(&self) -> bool {
                match self {
                    #(#expose_arms,)*
                }
            }
        }

        #into_response_impl
    };

    expanded.into()
}
