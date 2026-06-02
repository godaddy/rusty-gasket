//! OpenTelemetry initialization for distributed tracing and metrics export.
//!
//! When the `otlp` feature is enabled and `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
//! initializes OTLP span and metric exporters with:
//! - `ParentBased(TraceIdRatioBased)` sampling controlled by `OTEL_TRACES_SAMPLER_ARG`
//! - 60-second periodic metric reader
//! - Service resource attributes (name, version, environment)
//!
//! Returns an `OtelGuard` (when the `otlp` feature is enabled) that flushes
//! and shuts down providers on drop.
//!
//! Production-ready OpenTelemetry (OTLP) setup.

#[cfg(feature = "otlp")]
mod inner {
    use std::time::Duration;

    use opentelemetry::KeyValue;
    use opentelemetry_sdk::{Resource, metrics as sdkmetrics, trace as sdktrace};

    use crate::BoxError;

    /// Drop guard that keeps the OTEL tracer and meter providers alive.
    ///
    /// **Operators MUST call [`Self::shutdown`] from an async context
    /// before the guard is dropped.** The `Drop` fallback issues a
    /// blocking flush that can deadlock when invoked from inside the
    /// Tokio runtime (the batch span processor's worker is itself a
    /// Tokio task, so the runtime cannot make progress while the
    /// caller blocks waiting for it). The standard wiring is:
    ///
    /// ```ignore
    /// let guard = rusty_gasket::otel::try_init(...);
    /// // ... wire init_tracing_with_otel, run the server ...
    /// if let Some(Ok(guard)) = guard {
    ///     guard.shutdown().await;
    /// }
    /// ```
    ///
    /// The async path is bounded by an internal deadline so a
    /// degraded collector cannot stall process shutdown indefinitely;
    /// the `Drop` fallback has no such bound and exists only to
    /// surface a tracing::error rather than silently leak the SDK.
    ///
    /// Holds the providers behind `Option` so the async [`shutdown`]
    /// path can `take` them and the fallback `Drop` impl becomes a
    /// no-op — no `mem::forget`, no swap-in-and-leak of empty default
    /// providers.
    pub struct OtelGuard {
        tracer_provider: Option<sdktrace::SdkTracerProvider>,
        meter_provider: Option<sdkmetrics::SdkMeterProvider>,
    }

    impl std::fmt::Debug for OtelGuard {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OtelGuard").finish_non_exhaustive()
        }
    }

    impl OtelGuard {
        /// Get the tracer provider for building a `tracing-opentelemetry` layer.
        ///
        /// Returns `None` after [`Self::shutdown`] has been called.
        #[must_use]
        pub fn tracer_provider(&self) -> Option<&sdktrace::SdkTracerProvider> {
            self.tracer_provider.as_ref()
        }

        /// Flush and shut down the tracer and meter providers from an
        /// async context. Operators should call this before the guard
        /// is dropped, so the blocking flush runs on a dedicated
        /// blocking thread instead of stalling the runtime.
        ///
        /// Bounded by [`SHUTDOWN_DEADLINE`]: a JWKS-style hung collector
        /// (TCP half-close that never completes, blocked write to a
        /// degraded sidecar) MUST NOT prevent process shutdown on
        /// SIGTERM. Once the deadline elapses, the providers are
        /// abandoned in-flight and the function returns. Operators get
        /// a tracing::error so the degraded export is visible in logs.
        ///
        /// After this call, the `Drop` impl is a no-op.
        pub async fn shutdown(mut self) {
            let tracer = self.tracer_provider.take();
            let meter = self.meter_provider.take();
            let work = tokio::task::spawn_blocking(move || {
                (tracer.map(|t| t.shutdown()), meter.map(|m| m.shutdown()))
            });
            match tokio::time::timeout(SHUTDOWN_DEADLINE, work).await {
                Ok(Ok((trace_result, meter_result))) => {
                    if let Some(Err(e)) = trace_result {
                        tracing::error!(error = %e, "Failed to shut down OTEL tracer provider");
                    }
                    if let Some(Err(e)) = meter_result {
                        tracing::error!(error = %e, "Failed to shut down OTEL meter provider");
                    }
                }
                Ok(Err(join_err)) => {
                    tracing::error!(error = %join_err, "OTEL shutdown task panicked");
                }
                Err(_elapsed) => {
                    tracing::error!(
                        deadline_secs = SHUTDOWN_DEADLINE.as_secs(),
                        "OTEL shutdown exceeded deadline; abandoning provider flush"
                    );
                }
            }
        }
    }

    /// Maximum wall-clock time `shutdown()` will wait for the OTEL SDK
    /// to flush queued spans/metrics. Picked to be longer than a
    /// healthy collector round trip (~1 s) but shorter than a typical
    /// SIGTERM grace period (~10–30 s in k8s).
    const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

    impl Drop for OtelGuard {
        fn drop(&mut self) {
            // If `shutdown` was called, both options are `None` and this
            // is a no-op. Otherwise we attempt a best-effort blocking
            // shutdown — this can deadlock the batch span processor when
            // called from inside the runtime, which is why operators
            // should prefer the explicit async [`Self::shutdown`].
            if let Some(tracer) = self.tracer_provider.take()
                && let Err(e) = tracer.shutdown()
            {
                tracing::error!(error = %e, "Failed to shut down OTEL tracer provider on Drop");
            }
            if let Some(meter) = self.meter_provider.take()
                && let Err(e) = meter.shutdown()
            {
                tracing::error!(error = %e, "Failed to shut down OTEL meter provider on Drop");
            }
        }
    }

    /// Attempt to initialize OpenTelemetry tracing and metrics.
    ///
    /// Returns `Some(Ok(guard))` when `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
    /// `None` when it is not set (OTEL disabled), or `Some(Err(...))` on
    /// initialization failure.
    ///
    /// Does not install a tracing subscriber — call
    /// [`init_tracing_with_otel`](crate::observability::init_tracing_with_otel)
    /// after this succeeds to set up the dual-layer subscriber.
    #[must_use]
    pub fn try_init(
        service_name: &'static str,
        service_version: &'static str,
        deployment_env: &str,
    ) -> Option<Result<OtelGuard, BoxError>> {
        let raw = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
        if otlp_endpoint_is_configured(raw.as_deref()) {
            Some(init_otlp(service_name, service_version, deployment_env))
        } else {
            None
        }
    }

    /// Whether the supplied `OTEL_EXPORTER_OTLP_ENDPOINT` value should
    /// trigger OTLP initialization.
    ///
    /// `None` means the env var was unset; `Some("")` and `Some("   ")`
    /// are treated as unset because helm chart conditionals frequently
    /// render the value as an empty string and an empty endpoint is
    /// never a valid OTLP target.
    pub(super) fn otlp_endpoint_is_configured(raw: Option<&str>) -> bool {
        raw.is_some_and(|v| !v.trim().is_empty())
    }

    /// Parse the OTEL_TRACES_SAMPLER_ARG value into a clamped [0.0, 1.0] ratio.
    ///
    /// Falls back to the default 10% sampling rate when the value is missing,
    /// unparseable, or `NaN`. Out-of-range values (negative or > 1.0) are clamped.
    pub(super) fn parse_sample_ratio(raw: Option<String>) -> f64 {
        const DEFAULT: f64 = 0.1;
        raw.as_deref()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| !v.is_nan())
            .unwrap_or(DEFAULT)
            .clamp(0.0, 1.0)
    }

    fn build_resource(
        service_name: &'static str,
        service_version: &'static str,
        deployment_env: &str,
    ) -> Resource {
        Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", service_name),
                KeyValue::new("service.version", service_version),
                KeyValue::new("deployment.environment", deployment_env.to_owned()),
            ])
            .build()
    }

    fn init_otlp(
        service_name: &'static str,
        service_version: &'static str,
        deployment_env: &str,
    ) -> Result<OtelGuard, BoxError> {
        let resource = build_resource(service_name, service_version, deployment_env);

        // Span exporter: reads OTEL_EXPORTER_OTLP_ENDPOINT and
        // OTEL_EXPORTER_OTLP_HEADERS from environment automatically.
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| format!("Failed to build OTLP span exporter: {e}"))?;

        // Sampling ratio from OTEL_TRACES_SAMPLER_ARG (0.0–1.0, default 10%).
        let sample_ratio = parse_sample_ratio(std::env::var("OTEL_TRACES_SAMPLER_ARG").ok());

        let tracer_provider = sdktrace::SdkTracerProvider::builder()
            .with_sampler(sdktrace::Sampler::ParentBased(Box::new(
                sdktrace::Sampler::TraceIdRatioBased(sample_ratio),
            )))
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();

        // Metric exporter with 60-second periodic reader.
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| format!("Failed to build OTLP metric exporter: {e}"))?;

        let meter_provider = sdkmetrics::SdkMeterProvider::builder()
            .with_reader(
                sdkmetrics::PeriodicReader::builder(metric_exporter)
                    .with_interval(Duration::from_secs(60))
                    .build(),
            )
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        opentelemetry::global::set_meter_provider(meter_provider.clone());

        Ok(OtelGuard {
            tracer_provider: Some(tracer_provider),
            meter_provider: Some(meter_provider),
        })
    }

    /// Test-only constructor: wraps caller-supplied providers without
    /// touching the environment. Used by the async-shutdown smoke
    /// test so we don't need a live OTLP endpoint to exercise the
    /// Option<T>+take() drop path.
    #[cfg(test)]
    pub(super) fn guard_for_test(
        tracer: sdktrace::SdkTracerProvider,
        meter: sdkmetrics::SdkMeterProvider,
    ) -> OtelGuard {
        OtelGuard {
            tracer_provider: Some(tracer),
            meter_provider: Some(meter),
        }
    }
}

#[cfg(feature = "otlp")]
pub use inner::{OtelGuard, try_init};

#[cfg(all(test, feature = "otlp"))]
use inner::{guard_for_test, otlp_endpoint_is_configured, parse_sample_ratio};

#[cfg(all(test, feature = "otlp"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn try_init_returns_none_without_endpoint() {
        // Hard precondition: this test asserts the OTEL-disabled path, which
        // requires the env var to be absent. A previous version silently
        // skipped when the var was set, masking the test in any CI that
        // exports it. Fail loudly instead so the test never lies about
        // having run.
        assert!(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err(),
            "OTEL_EXPORTER_OTLP_ENDPOINT must be unset for this test; \
             clear it in the test runner environment to run otel tests."
        );
        let result = try_init("test-svc", "0.1.0", "test");
        assert!(
            result.is_none(),
            "try_init should return None when OTEL_EXPORTER_OTLP_ENDPOINT is not set"
        );
    }

    #[test]
    fn sample_ratio_uses_default_when_unset() {
        let r = parse_sample_ratio(None);
        assert!((r - 0.1).abs() < f64::EPSILON, "expected 0.1, got {r}");
    }

    #[test]
    fn sample_ratio_uses_default_when_unparseable() {
        let r = parse_sample_ratio(Some("not a number".to_string()));
        assert!((r - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_clamps_above_one() {
        assert!((parse_sample_ratio(Some("5.0".to_string())) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_clamps_below_zero() {
        assert!((parse_sample_ratio(Some("-0.5".to_string()))).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_accepts_zero() {
        assert!(parse_sample_ratio(Some("0.0".to_string())).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_accepts_one() {
        assert!((parse_sample_ratio(Some("1.0".to_string())) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_accepts_midrange() {
        assert!((parse_sample_ratio(Some("0.25".to_string())) - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_ratio_rejects_nan() {
        // NaN comparisons are weird; clamp() on NaN would return NaN. The
        // filter(!is_nan) guard should drop into the 0.1 default.
        let r = parse_sample_ratio(Some("NaN".to_string()));
        assert!((r - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn otlp_endpoint_unset_disables_otlp() {
        assert!(!otlp_endpoint_is_configured(None));
    }

    #[test]
    fn otlp_endpoint_empty_disables_otlp() {
        // helm conditionals frequently render the variable as an empty
        // string; that should be treated the same as unset rather than
        // attempting to initialize against an empty endpoint.
        assert!(!otlp_endpoint_is_configured(Some("")));
    }

    #[test]
    fn otlp_endpoint_whitespace_disables_otlp() {
        assert!(!otlp_endpoint_is_configured(Some("   ")));
        assert!(!otlp_endpoint_is_configured(Some("\t\n")));
    }

    #[test]
    fn otlp_endpoint_real_value_enables_otlp() {
        assert!(otlp_endpoint_is_configured(Some("http://collector:4317")));
        assert!(otlp_endpoint_is_configured(Some(" http://collector:4317 ")));
    }

    /// Exercises the `Option<T>::take()` shutdown path:
    ///
    /// 1. The async `shutdown` call must complete without panicking and
    ///    drain both providers.
    /// 2. After `shutdown`, the `Drop` impl must be a no-op — the
    ///    refactor away from `ManuallyDrop`/`mem::forget` relies on the
    ///    `take()` pattern so a second shutdown attempt in `drop` is
    ///    naturally skipped. Without that, dropping the empty providers
    ///    again would either re-emit an SDK error or, before the
    ///    refactor, leak two empty SDK providers via `mem::forget`.
    ///
    /// This used to be the single biggest "look what the AI did"
    /// finding from the deep-review skill; the test pins down the
    /// behavior so it can't regress silently.
    #[tokio::test]
    async fn shutdown_then_drop_is_idempotent() {
        let tracer = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let meter = opentelemetry_sdk::metrics::SdkMeterProvider::builder().build();
        let guard = guard_for_test(tracer, meter);

        // Pre-shutdown: both providers are present.
        assert!(guard.tracer_provider().is_some());

        // Drains both providers on a spawn_blocking thread; must not
        // panic, must not stall (the test runtime has no other tasks
        // competing for the blocking pool here).
        guard.shutdown().await;

        // `guard` is consumed by shutdown; no Drop runs on it. The
        // implicit assertion is that we reached this line without
        // panic or hang from the async path.
    }

    /// Drop-only path: when `shutdown` is never called (operator forgot
    /// or panicked before the explicit shutdown), the `Drop` impl must
    /// still flush both providers without panicking. This is the
    /// fallback that exists exactly to keep the test suite honest
    /// about the "we always release the SDK providers" invariant.
    #[test]
    fn drop_without_shutdown_does_not_panic() {
        let tracer = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let meter = opentelemetry_sdk::metrics::SdkMeterProvider::builder().build();
        let guard = guard_for_test(tracer, meter);
        drop(guard);
    }
}
