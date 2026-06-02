//! Security-tagged JSON tracing formatter.
//!
//! Many SIEM and log-router pipelines treat a top-level `tags` array as a
//! routing hint. [`SecurityJsonFormat`] preserves the normal
//! `tracing-subscriber` JSON event shape and adds `"security"` to events
//! emitted by configured security-sensitive module paths.

use tracing_subscriber::fmt::format::Writer;

/// JSON formatter that tags security-relevant log events.
///
/// The formatter wraps `tracing-subscriber`'s standard JSON formatter.
/// Events whose target starts with the configured prefix receive a
/// top-level `"tags":["security"]` field. Other events pass through
/// unchanged.
///
/// # Examples
///
/// ```ignore
/// use rusty_gasket::observability::SecurityJsonFormat;
///
/// tracing_subscriber::fmt()
///     .fmt_fields(tracing_subscriber::fmt::format::JsonFields::new())
///     .event_format(SecurityJsonFormat::new("my_service::auth"))
///     .init();
/// ```
#[derive(Debug)]
pub struct SecurityJsonFormat {
    inner: tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Json>,
    security_target_prefix: &'static str,
}

impl SecurityJsonFormat {
    /// Create a formatter that tags events from the given target prefix.
    ///
    /// For Rust module targets, this is usually the path of the auth or
    /// authorization module, such as `"my_service::auth"`.
    #[must_use]
    pub fn new(security_target_prefix: &'static str) -> Self {
        Self {
            inner: tracing_subscriber::fmt::format::Format::default()
                .json()
                .with_target(true),
            security_target_prefix,
        }
    }

    /// Create a formatter for Rusty Gasket auth events.
    #[must_use]
    pub fn default_gasket() -> Self {
        Self::new("rusty_gasket_auth")
    }

    /// Return the module target prefix that will be tagged as security-related.
    #[must_use]
    pub const fn security_target_prefix(&self) -> &'static str {
        self.security_target_prefix
    }

    /// Initialize the global tracing subscriber with this formatter.
    ///
    /// Use this instead of [`init_tracing`](super::init_tracing) when the
    /// deployment needs SIEM-routable security event tags.
    pub fn init(self) {
        use tracing_subscriber::EnvFilter;
        use tracing_subscriber::prelude::*;

        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(tracing_subscriber::fmt::format::JsonFields::new())
                    .event_format(self)
                    .with_filter(filter),
            )
            .init();

        tracing::info!("Initialized SecurityJsonFormat logging");
    }
}

impl Default for SecurityJsonFormat {
    fn default() -> Self {
        Self::default_gasket()
    }
}

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for SecurityJsonFormat
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> tracing_subscriber::fmt::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        context: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let target = event.metadata().target();
        let is_security_event = target.starts_with(self.security_target_prefix);

        if !is_security_event {
            return self.inner.format_event(context, writer, event);
        }

        // Render to an intermediate string so we can preserve the standard
        // JSON event fields and inject one routing tag at the top level.
        let mut buffer = String::new();
        self.inner
            .format_event(context, Writer::new(&mut buffer), event)?;

        let trimmed = buffer.trim_end();
        if let Some(rest) = trimmed.strip_prefix('{') {
            write!(writer, "{{\"tags\":[\"security\"],{rest}")?;
            writeln!(writer)
        } else {
            write!(writer, "{buffer}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefix_targets_rusty_gasket_auth() {
        let formatter = SecurityJsonFormat::default();
        assert_eq!(formatter.security_target_prefix(), "rusty_gasket_auth");
    }

    #[test]
    fn custom_prefix_is_preserved() {
        let formatter = SecurityJsonFormat::new("my_app::auth");
        assert_eq!(formatter.security_target_prefix(), "my_app::auth");
    }

    #[test]
    fn debug_names_the_formatter() {
        let formatter = SecurityJsonFormat::default();
        let debug = format!("{formatter:?}");
        assert!(debug.contains("SecurityJsonFormat"));
    }
}
