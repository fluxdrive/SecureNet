//! Observability setup — OpenTelemetry + tracing.
//!
//! Call `init_telemetry` once at service startup.  It:
//! 1. Initialises a `tracing-subscriber` with JSON formatting.
//! 2. Sets up an OTLP exporter pointing at Jaeger.
//! 3. Bridges `tracing` spans to OpenTelemetry.
//!
//! All inter-service HTTP calls must propagate the W3C `traceparent` header.
//! Use `inject_context` before sending and `extract_context` on receipt to
//! maintain trace continuity across service boundaries.

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// ── Init ──────────────────────────────────────────────────────────────────────

/// Initialise the global tracing + OpenTelemetry pipeline.
///
/// # Arguments
///
/// * `service_name`     — e.g. `"api-gateway"`.  Appears in Jaeger's service list.
/// * `jaeger_endpoint`  — OTLP/gRPC endpoint, e.g. `"http://jaeger:4317"`.
///                        Pass `None` to disable OTLP export (useful in tests).
///
/// # Panics
///
/// Panics if called more than once (tracing subscriber is a global).
pub fn init_telemetry(
    service_name:    &str,
    jaeger_endpoint: Option<&str>,
) -> anyhow::Result<()> {
    // ── OTLP exporter (optional) ──────────────────────────────────────────────
    let otel_layer = if let Some(endpoint) = jaeger_endpoint {
        use opentelemetry_otlp::WithExportConfig;

        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(
                opentelemetry_sdk::trace::config()
                    .with_resource(opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new(
                            "service.name",
                            service_name.to_string(),
                        ),
                    ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    // ── tracing-subscriber ────────────────────────────────────────────────────
    let filter  = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt     = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(fmt);

    // Conditionally add the OTLP layer.
    if let Some(otel) = otel_layer {
        registry.with(otel).init();
    } else {
        registry.init();
    }

    Ok(())
}

/// Flush all pending spans and shut down the OTLP exporter.
///
/// Call this before the process exits to avoid losing the last few spans.
pub fn shutdown_telemetry() {
    opentelemetry::global::shutdown_tracer_provider();
}

// ── W3C Trace Context propagation ─────────────────────────────────────────────

/// Inject the current span context into an outbound request's headers.
///
/// This sets the `traceparent` (and optionally `tracestate`) HTTP header so
/// the receiving service can continue the same trace.
///
/// # Example
///
/// ```rust
/// let mut headers = reqwest::header::HeaderMap::new();
/// inject_context(&mut headers);
/// let resp = client.get(url).headers(headers).send().await?;
/// ```
pub fn inject_context(headers: &mut reqwest::header::HeaderMap) {
    let propagator = TraceContextPropagator::new();
    let cx         = tracing_opentelemetry::OpenTelemetrySpanExt::context(
        &tracing::Span::current(),
    );

    let mut carrier = HeaderMapCarrier(headers);
    propagator.inject_context(&cx, &mut carrier);
}

/// Extract a span context from inbound request headers.
///
/// Returns an `opentelemetry::Context` that can be set as the parent of the
/// current span with `span.set_parent(cx)`.
///
/// # Example
///
/// ```rust
/// // In an axum handler:
/// async fn handler(headers: axum::http::HeaderMap) -> ... {
///     let cx = extract_context(&headers);
///     tracing::Span::current().set_parent(cx);
///     ...
/// }
/// ```
pub fn extract_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    let propagator = TraceContextPropagator::new();
    let carrier    = AxumHeaderCarrier(headers);
    propagator.extract(&carrier)
}

// ── HeaderMap carriers ────────────────────────────────────────────────────────
// OpenTelemetry's TextMapPropagator works against a generic `Injector` /
// `Extractor` trait.  We provide thin wrappers for both reqwest and axum header
// maps.

struct HeaderMapCarrier<'a>(&'a mut reqwest::header::HeaderMap);

impl opentelemetry::propagation::Injector for HeaderMapCarrier<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name)  = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

struct AxumHeaderCarrier<'a>(&'a axum::http::HeaderMap);

impl opentelemetry::propagation::Extractor for AxumHeaderCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}
