//! Optional `sharded-sink`-backed observability.
//!
//! This module is gated behind the `sharded-sink` feature and is **off by
//! default**. It lets a service trade a small amount of log/telemetry
//! *retention* for flat producer latency under bursty load: instead of writing
//! each log line (or audit event) inline on the request path — where a slow or
//! contended sink adds tail latency — the record is handed to a
//! [`sharded_sink::ShardedSink`] and the real write happens off the request
//! path on drain workers. When the sink is overloaded it **sheds** records
//! rather than blocking.
//!
//! Everything here is opt-in and composable with the normal stack:
//!
//! - [`init_tracing_sharded`] installs the same `tracing` formatter as
//!   [`init_tracing`](crate::observability::init_tracing), but routes the
//!   *formatted bytes* through a sharded sink to the real writer (stdout). The
//!   format is unchanged; only the write is offloaded.
//! - [`ShardedAuditLogger`] wraps any [`AuditLogger`](crate::auth::AuditLogger)
//!   so auth events are buffered and emitted off the auth path.
//!
//! ## Tradeoffs (document these for your team)
//!
//! - **Drop under overload.** If the drain cannot keep up, records are dropped,
//!   not buffered unboundedly and not blocked on. This is the point.
//! - **Cross-shard ordering.** With more than one shard, records are FIFO only
//!   within a shard. The default is **one shard**, which preserves global order
//!   while still moving the write off the request path; raise `shards` only if
//!   producer-thread contention shows up in profiles, and accept reordering
//!   (log/telemetry consumers re-sort by timestamp).

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use sharded_sink::{ShardedSink, SinkAction, SinkConfig};

use crate::BoxError;
use crate::config::Environment;

/// Configuration for the optional `sharded-sink`-backed observability paths.
///
/// Deserializes from an [`AppConfig`](crate::config::AppConfig) section (e.g.
/// `[observability.sharded_sink]`) and is **off by default**. When `enabled` is
/// false, the helper constructors here behave exactly like the non-sharded
/// equivalents.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ShardedSinkConfig {
    /// Master switch. When false, sharded paths fall back to inline behavior.
    pub enabled: bool,
    /// Number of shards. Default `1` (global ordering, write still offloaded).
    /// Raise to reduce producer contention at the cost of cross-shard ordering.
    pub shards: usize,
    /// Capacity of each shard ring, in records.
    pub ring_capacity: usize,
    /// Maximum records a drain worker batches before writing.
    pub drain_batch: usize,
    /// How long a drain worker sleeps when its shard is empty, in microseconds.
    pub idle_sleep_micros: u64,
    /// Maximum seconds a guard `shutdown` waits for drain workers. `None` waits
    /// indefinitely.
    pub shutdown_timeout_secs: Option<u64>,
}

impl Default for ShardedSinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shards: 1,
            ring_capacity: 8192,
            drain_batch: 256,
            idle_sleep_micros: 100,
            shutdown_timeout_secs: Some(5),
        }
    }
}

impl ShardedSinkConfig {
    /// Build a [`sharded_sink::SinkConfig`] from these settings with the given
    /// stable sink name.
    fn to_sink_config(&self, name: &'static str) -> SinkConfig {
        let mut cfg = SinkConfig::default();
        cfg.name = name;
        cfg.shards = self.shards.max(1);
        cfg.ring_capacity = self.ring_capacity.max(1);
        cfg.drain_batch = self.drain_batch.max(1);
        cfg.idle_sleep = Duration::from_micros(self.idle_sleep_micros.max(1));
        cfg.shutdown_timeout = self.shutdown_timeout_secs.map(Duration::from_secs);
        cfg
    }
}

// ---- log write offload -------------------------------------------------------

/// A fully formatted log line awaiting write.
type LogLine = Vec<u8>;

/// Drain action that writes batched, already-formatted log lines to the real
/// underlying writer (e.g. stdout). Runs on drain workers, off the request path.
struct WriteDrain<W: Write + Send + 'static> {
    writer: std::sync::Mutex<W>,
}

impl<W: Write + Send + 'static> SinkAction<LogLine> for WriteDrain<W> {
    async fn drain(&self, batch: &mut Vec<LogLine>) {
        // No `.await` while the lock is held. With the default single shard
        // there is exactly one drainer; with more shards this serializes
        // writes, which is what keeps interleaved lines intact.
        let mut writer = match self.writer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Best-effort: a write/flush error on the log sink is dropped (lossy).
        for line in batch.iter() {
            let _written = writer.write_all(line);
        }
        let _flushed = writer.flush();
    }
}

/// A [`MakeWriter`](tracing_subscriber::fmt::MakeWriter) that hands each
/// formatted log line to a sharded sink instead of writing it inline.
#[derive(Clone)]
struct ShardedMakeWriter {
    sink: Arc<ShardedSink<LogLine>>,
}

/// Per-event writer: accumulates one formatted event, then pushes it to the
/// sink on drop (the `fmt` layer writes one event per writer and drops it).
struct ShardedLineWriter {
    sink: Arc<ShardedSink<LogLine>>,
    buf: Vec<u8>,
}

impl Write for ShardedLineWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ShardedLineWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            // Lossy by design: a `false` here means the line was shed under
            // overload, which is the retention-for-latency tradeoff.
            let line = std::mem::take(&mut self.buf);
            let _ = self.sink.push(line);
        }
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for ShardedMakeWriter {
    type Writer = ShardedLineWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        ShardedLineWriter {
            sink: Arc::clone(&self.sink),
            buf: Vec::new(),
        }
    }
}

/// Guard returned by the sharded tracing initializers. Hold it for the life of
/// the process and call [`shutdown`](ShardedLogGuard::shutdown) before exit to
/// flush buffered log lines, mirroring [`OtelGuard`](crate::otel::OtelGuard).
///
/// Dropping the guard without calling `shutdown` is best-effort: drain workers
/// are signalled to stop but buffered lines may not be flushed.
#[derive(Debug)]
pub struct ShardedLogGuard {
    sink: Option<Arc<ShardedSink<LogLine>>>,
}

impl ShardedLogGuard {
    /// Flush buffered log lines and stop the drain workers.
    ///
    /// A no-op when sharded logging was disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the drain workers do not finish within the
    /// configured `shutdown_timeout_secs`, or if a worker panicked.
    pub async fn shutdown(self) -> Result<(), BoxError> {
        if let Some(sink) = self.sink {
            sink.shutdown().await.map_err(BoxError::from)?;
        }
        Ok(())
    }
}

/// Spawn a log sink fronting `writer`, returning its make-writer and a guard.
fn spawn_log_sink<W: Write + Send + 'static>(
    cfg: &ShardedSinkConfig,
    writer: W,
) -> (ShardedMakeWriter, ShardedLogGuard) {
    let action = Arc::new(WriteDrain {
        writer: std::sync::Mutex::new(writer),
    });
    let sink = Arc::new(ShardedSink::spawn_default_overload(
        cfg.to_sink_config("rusty-gasket-log"),
        action,
    ));
    (
        ShardedMakeWriter {
            sink: Arc::clone(&sink),
        },
        ShardedLogGuard { sink: Some(sink) },
    )
}

/// Like [`init_tracing`](crate::observability::init_tracing), but when
/// `cfg.enabled` is set the formatted log bytes are written through a
/// `sharded-sink` (off the request path, lossy under overload) instead of
/// inline. The log *format* is identical either way.
///
/// Returns a [`ShardedLogGuard`]; hold it until the end of `main` and call
/// [`shutdown`](ShardedLogGuard::shutdown) to flush. When disabled, this is
/// equivalent to `init_tracing` and the returned guard is inert.
///
/// # Example
///
/// ```no_run
/// use rusty_gasket::config::{AppConfig, Environment};
/// use rusty_gasket::observability::{ShardedSinkConfig, init_tracing_sharded};
///
/// # async fn run(config: &AppConfig) -> Result<(), rusty_gasket::BoxError> {
/// // Off by default; teams opt in via `[observability.sharded_sink]` in config.
/// let sharded: ShardedSinkConfig = config.section_or_default("sharded_sink")?;
/// let log_guard = init_tracing_sharded(Environment::Production, &sharded);
///
/// // ... run the server ...
///
/// log_guard.shutdown().await?; // flush buffered logs before exit
/// # Ok(())
/// # }
/// ```
///
/// # Panics
///
/// Panics if a global tracing subscriber is already installed, or (when
/// enabled) if called outside a Tokio runtime with the time driver enabled —
/// the sink spawns drain workers that use Tokio timers.
#[must_use]
pub fn init_tracing_sharded(env: Environment, cfg: &ShardedSinkConfig) -> ShardedLogGuard {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    if !cfg.enabled {
        super::init_tracing(env);
        return ShardedLogGuard { sink: None };
    }

    let (make_writer, guard) = spawn_log_sink(cfg, io::stdout());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);

    match env {
        Environment::Local => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_writer(make_writer)
                .pretty();
            registry.with(fmt_layer).init();
        }
        _ => {
            #[cfg(feature = "json-log")]
            {
                let fmt_layer = tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_writer(make_writer);
                registry.with(fmt_layer).init();
            }
            #[cfg(not(feature = "json-log"))]
            {
                let fmt_layer = tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_writer(make_writer);
                registry.with(fmt_layer).init();
            }
        }
    }

    guard
}

/// Like [`init_tracing_with_otel`](crate::observability::init_tracing_with_otel),
/// but routes the formatted log bytes through a `sharded-sink` when
/// `cfg.enabled` is set. The OpenTelemetry span/metric layer is unchanged; only
/// the log-write path is offloaded.
///
/// Returns a [`ShardedLogGuard`] for the log sink (independent of the
/// [`OtelGuard`](crate::otel::OtelGuard) that owns span/metric flush).
///
/// # Panics
///
/// Panics if a global tracing subscriber is already installed, or (when
/// enabled) if called outside a Tokio runtime with the time driver enabled.
#[cfg(feature = "otlp")]
#[must_use]
pub fn init_tracing_with_otel_sharded(
    env: Environment,
    provider: &opentelemetry_sdk::trace::SdkTracerProvider,
    service_name: &'static str,
    cfg: &ShardedSinkConfig,
) -> ShardedLogGuard {
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    if !cfg.enabled {
        super::init_tracing_with_otel(env, provider, service_name);
        return ShardedLogGuard { sink: None };
    }

    let (make_writer, guard) = spawn_log_sink(cfg, io::stdout());
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,h2=off,hyper=off,rustls=off,tonic=off"));
    let tracer = provider.tracer(service_name);
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let registry = tracing_subscriber::registry().with(filter).with(otel_layer);

    match env {
        Environment::Local => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_writer(make_writer)
                .pretty();
            registry.with(fmt_layer).init();
        }
        _ => {
            #[cfg(feature = "json-log")]
            {
                let fmt_layer = tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_writer(make_writer);
                registry.with(fmt_layer).init();
            }
            #[cfg(not(feature = "json-log"))]
            {
                let fmt_layer = tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_writer(make_writer);
                registry.with(fmt_layer).init();
            }
        }
    }

    guard
}

// ---- audit event offload -----------------------------------------------------

#[cfg(feature = "auth")]
mod audit_offload {
    use super::{Arc, ShardedSinkConfig};
    use crate::auth::{AuditLogger, AuditLoggerHandle, AuthAuditEvent};
    use sharded_sink::{ShardedSink, SinkAction};

    /// Drain action that forwards buffered audit events to the real logger.
    struct AuditDrain {
        inner: AuditLoggerHandle,
    }

    impl SinkAction<AuthAuditEvent> for AuditDrain {
        async fn drain(&self, batch: &mut Vec<AuthAuditEvent>) {
            for event in batch.iter() {
                self.inner.logger().log_auth_event(event);
            }
        }
    }

    /// An [`AuditLogger`] that buffers auth events through a `sharded-sink` and
    /// forwards them to an inner logger on drain workers, off the auth path.
    ///
    /// Construct via [`ShardedAuditLogger::wrap`], which returns an
    /// [`AuditLoggerHandle`] ready for the auth chain. When the config is
    /// disabled, `wrap` returns the inner handle unchanged.
    #[derive(Debug)]
    pub struct ShardedAuditLogger {
        sink: Arc<ShardedSink<AuthAuditEvent>>,
    }

    impl ShardedAuditLogger {
        /// Wrap `inner` so audit events are emitted off the request path.
        ///
        /// Returns `inner` unchanged when `cfg.enabled` is false.
        ///
        /// # Panics
        ///
        /// When enabled, panics if called outside a Tokio runtime with the time
        /// driver enabled (the sink spawns drain workers).
        #[must_use]
        pub fn wrap(inner: AuditLoggerHandle, cfg: &ShardedSinkConfig) -> AuditLoggerHandle {
            if !cfg.enabled {
                return inner;
            }
            let sink = Arc::new(ShardedSink::spawn_default_overload(
                cfg.to_sink_config("rusty-gasket-audit"),
                Arc::new(AuditDrain { inner }),
            ));
            AuditLoggerHandle::shared(Arc::new(ShardedAuditLogger { sink }))
        }
    }

    impl AuditLogger for ShardedAuditLogger {
        fn log_auth_event(&self, event: &AuthAuditEvent) {
            // Lossy under overload — sheds audit events rather than blocking
            // the auth path.
            let _ = self.sink.push(event.clone());
        }
    }
}

#[cfg(feature = "auth")]
pub use audit_offload::ShardedAuditLogger;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_disabled_single_shard() {
        let cfg = ShardedSinkConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.shards, 1);
    }

    #[test]
    fn to_sink_config_maps_and_clamps_fields() {
        let cfg = ShardedSinkConfig {
            enabled: true,
            shards: 0,
            ring_capacity: 0,
            drain_batch: 0,
            idle_sleep_micros: 0,
            shutdown_timeout_secs: None,
            ..Default::default()
        };
        let sink_cfg = cfg.to_sink_config("test");
        assert_eq!(sink_cfg.name, "test");
        assert_eq!(sink_cfg.shards, 1, "shards clamped to >= 1");
        assert_eq!(sink_cfg.ring_capacity, 1, "ring_capacity clamped to >= 1");
        assert_eq!(sink_cfg.drain_batch, 1, "drain_batch clamped to >= 1");
        assert_eq!(sink_cfg.shutdown_timeout, None);
    }

    #[derive(Clone)]
    struct BufWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for BufWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut guard = self.0.lock().unwrap_or_else(|p| p.into_inner());
            guard.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn formatted_lines_are_written_off_thread() {
        let buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let cfg = ShardedSinkConfig {
            enabled: true,
            ..Default::default()
        };
        let action = Arc::new(WriteDrain {
            writer: std::sync::Mutex::new(BufWriter(Arc::clone(&buf))),
        });
        let sink = ShardedSink::spawn_default_overload(cfg.to_sink_config("test-log"), action);

        for i in 0..200_u32 {
            assert!(sink.push(format!("line {i}\n").into_bytes()));
        }
        sink.shutdown().await.expect("shutdown");

        let written = String::from_utf8(buf.lock().expect("buf lock").clone()).expect("utf8");
        assert_eq!(written.lines().count(), 200);
    }

    #[cfg(feature = "auth")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_wrap_disabled_forwards_inline() {
        use crate::auth::{AuditLogger, AuditLoggerHandle, AuthAuditEvent, AuthAuditOutcome};
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct Counting(Arc<AtomicUsize>);
        impl AuditLogger for Counting {
            fn log_auth_event(&self, _event: &AuthAuditEvent) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let inner = AuditLoggerHandle::new(Counting(Arc::clone(&count)));
        let cfg = ShardedSinkConfig::default(); // disabled
        let handle = ShardedAuditLogger::wrap(inner, &cfg);

        handle.logger().log_auth_event(&AuthAuditEvent::new(
            "rid",
            "1.2.3.4",
            AuthAuditOutcome::Success,
        ));
        // Disabled => pass-through, synchronous.
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "auth")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_wrap_enabled_forwards_off_path() {
        use crate::auth::{AuditLogger, AuditLoggerHandle, AuthAuditEvent, AuthAuditOutcome};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        #[derive(Clone)]
        struct Counting(Arc<AtomicUsize>);
        impl AuditLogger for Counting {
            fn log_auth_event(&self, _event: &AuthAuditEvent) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let inner = AuditLoggerHandle::new(Counting(Arc::clone(&count)));
        let cfg = ShardedSinkConfig {
            enabled: true,
            ..Default::default()
        };
        let handle = ShardedAuditLogger::wrap(inner, &cfg);

        for _ in 0..50 {
            handle.logger().log_auth_event(&AuthAuditEvent::new(
                "rid",
                "1.2.3.4",
                AuthAuditOutcome::Success,
            ));
        }

        // Drain happens off-path; wait for the workers to forward all events.
        let mut forwarded = 0;
        for _ in 0..100 {
            forwarded = count.load(Ordering::SeqCst);
            if forwarded == 50 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(forwarded, 50, "all audit events forwarded to inner logger");
    }
}
