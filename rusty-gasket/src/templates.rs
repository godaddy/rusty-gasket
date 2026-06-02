//! HTML templating battery built on [`minijinja`].
//!
//! [`Templates`] wraps a configured minijinja [`Environment`] and renders named
//! templates to either a `String` or an axum HTML [`Response`]. HTML
//! autoescaping is on by default for `.html`/`.htm`/`.xml` templates, so values
//! interpolated from request data are escaped unless explicitly marked safe —
//! the reason this lives in the framework rather than each service hand-rolling
//! a renderer.
//!
//! Build templates compiled into the binary via [`Templates::builder`] (the
//! production default — the deployed artifact is self-contained), or load them
//! lazily from a directory via [`Templates::from_dir`] (convenient in
//! development).
//!
//! ```
//! use rusty_gasket::templates::Templates;
//!
//! let templates = Templates::builder()
//!     .template("hello.html", "<h1>Hello {{ name }}</h1>")
//!     .build()
//!     .expect("templates compile");
//! let html = templates
//!     .render("hello.html", minijinja::context! { name => "world" })
//!     .expect("render");
//! assert_eq!(html, "<h1>Hello world</h1>");
//! ```

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use minijinja::Environment;
use serde::Serialize;

use crate::BoxError;

/// A shared, cheaply-cloneable set of compiled templates.
///
/// Clones share the same underlying [`Environment`] (an `Arc` inside), so a
/// `Templates` is well-suited as axum router state.
#[derive(Clone)]
pub struct Templates {
    env: Arc<Environment<'static>>,
}

impl std::fmt::Debug for Templates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Templates").finish_non_exhaustive()
    }
}

impl Templates {
    /// Start building a [`Templates`] from in-memory template sources.
    pub fn builder() -> TemplatesBuilder {
        TemplatesBuilder::default()
    }

    /// Load templates lazily from `dir`, by file name relative to it.
    ///
    /// Convenient in development (templates are read from disk on first use).
    /// For production prefer [`Templates::builder`] with sources compiled into
    /// the binary (e.g. via `include_str!`) so the deployed artifact is
    /// self-contained and can't fail on a missing file at runtime.
    #[must_use]
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        let mut env = Environment::new();
        env.set_loader(minijinja::path_loader(dir.as_ref()));
        Self { env: Arc::new(env) }
    }

    /// Render template `name` with `context` to a `String`.
    ///
    /// # Errors
    /// Returns an error if the template is unknown or rendering fails (for
    /// example a type error in an expression).
    pub fn render<S: Serialize>(&self, name: &str, context: S) -> Result<String, BoxError> {
        let template = self
            .env
            .get_template(name)
            .map_err(|e| format!("template '{name}' not found: {e}"))?;
        template
            .render(context)
            .map_err(|e| format!("rendering template '{name}' failed: {e}").into())
    }

    /// Render template `name` to an HTML [`Response`].
    ///
    /// On success: `200 OK` with `Content-Type: text/html`. On failure the
    /// error is logged and a generic `500 Internal Server Error` is returned —
    /// template internals and context values are never leaked to the client.
    #[must_use]
    pub fn render_html<S: Serialize>(&self, name: &str, context: S) -> Response {
        match self.render(name, context) {
            Ok(body) => Html(body).into_response(),
            Err(error) => {
                tracing::error!(template = name, %error, "template render failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "template render error").into_response()
            }
        }
    }
}

/// Builder for [`Templates`] from in-memory template sources.
#[derive(Default)]
#[must_use = "TemplatesBuilder does nothing until `build` is called"]
pub struct TemplatesBuilder {
    sources: Vec<(String, String)>,
}

impl std::fmt::Debug for TemplatesBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplatesBuilder")
            .field("count", &self.sources.len())
            .finish()
    }
}

impl TemplatesBuilder {
    /// Add a named template from its source string.
    ///
    /// The name's extension drives autoescaping (`.html` escapes; `.txt` does
    /// not), so give HTML templates a `.html` name.
    pub fn template(mut self, name: impl Into<String>, source: impl Into<String>) -> Self {
        self.sources.push((name.into(), source.into()));
        self
    }

    /// Compile the added templates.
    ///
    /// # Errors
    /// Returns an error if any template fails to compile (a syntax error),
    /// naming the offending template.
    pub fn build(self) -> Result<Templates, BoxError> {
        let mut env = Environment::new();
        for (name, source) in self.sources {
            env.add_template_owned(name.clone(), source)
                .map_err(|e| format!("compiling template '{name}' failed: {e}"))?;
        }
        Ok(Templates { env: Arc::new(env) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use axum::body::to_bytes;
    use axum::http::header;
    use minijinja::context;

    use super::*;

    fn templates() -> Templates {
        Templates::builder()
            .template("hello.html", "<p>Hello {{ name }}</p>")
            .template("plain.txt", "Hi {{ name }}")
            .build()
            .unwrap()
    }

    #[test]
    fn renders_to_string() {
        let out = templates()
            .render("hello.html", context! { name => "Jay" })
            .unwrap();
        assert_eq!(out, "<p>Hello Jay</p>");
    }

    #[test]
    fn html_template_autoescapes() {
        let out = templates()
            .render("hello.html", context! { name => "<script>" })
            .unwrap();
        assert_eq!(out, "<p>Hello &lt;script&gt;</p>");
    }

    #[test]
    fn non_html_template_does_not_escape() {
        let out = templates()
            .render("plain.txt", context! { name => "<x>" })
            .unwrap();
        assert_eq!(out, "Hi <x>");
    }

    #[test]
    fn unknown_template_is_an_error() {
        assert!(templates().render("missing.html", context! {}).is_err());
    }

    #[test]
    fn build_rejects_invalid_syntax() {
        let result = Templates::builder()
            .template("bad.html", "{{ unclosed")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn from_dir_loads_templates() {
        let dir = std::env::temp_dir().join(format!("rg-templates-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("page.html"), "<h1>{{ title }}</h1>").unwrap();

        let rendered = Templates::from_dir(&dir)
            .render("page.html", context! { title => "Hi" })
            .unwrap();
        assert_eq!(rendered, "<h1>Hi</h1>");

        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn render_html_returns_ok_html() {
        let response = templates().render_html("hello.html", context! { name => "Jay" });
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.starts_with("text/html"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"<p>Hello Jay</p>");
    }

    #[tokio::test]
    async fn render_html_error_is_500() {
        let response = templates().render_html("missing.html", context! {});
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
