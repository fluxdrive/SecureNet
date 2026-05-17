//! Chaos engineering middleware.
//!
//! This Tower [`Layer`] injects random faults into the request path to verify
//! that the system handles them gracefully.  It is compiled unconditionally but
//! is a no-op unless the `CHAOS_DELAY_P` or `CHAOS_DROP_P` environment
//! variables are set to non-zero values.
//!
//! ## Fault types
//!
//! | Fault   | Env var        | Behaviour                                  |
//! |---------|----------------|--------------------------------------------|
//! | Delay   | `CHAOS_DELAY_P`| Sleep 100–500 ms before forwarding request |
//! | Drop    | `CHAOS_DROP_P` | Return `503 Service Unavailable` immediately|
//!
//! Both probabilities are floats in `[0.0, 1.0]`.
//!
//! ## Observability
//!
//! Every injected fault emits a `tracing` event at `WARN` level with
//! `chaos.injected = true` so it appears as an annotated span in Jaeger.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::http::{Request, Response, StatusCode};
use axum::body::Body;
use rand::Rng;
use tower::{Layer, Service};
use tracing::warn;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Runtime-configurable chaos parameters.
///
/// Read once at startup from environment variables; stored in the Layer.
#[derive(Debug, Clone, Copy)]
pub struct ChaosConfig {
    /// Probability `[0, 1]` of injecting a random delay.
    pub delay_p: f64,
    /// Probability `[0, 1]` of dropping the request entirely.
    pub drop_p:  f64,
    /// Minimum delay in milliseconds.
    pub delay_min_ms: u64,
    /// Maximum delay in milliseconds.
    pub delay_max_ms: u64,
}

impl ChaosConfig {
    /// Read config from environment variables, falling back to zero (no chaos).
    pub fn from_env() -> Self {
        let delay_p = std::env::var("CHAOS_DELAY_P")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0_f64)
            .clamp(0.0, 1.0);

        let drop_p = std::env::var("CHAOS_DROP_P")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0_f64)
            .clamp(0.0, 1.0);

        Self {
            delay_p,
            drop_p,
            delay_min_ms: 100,
            delay_max_ms: 500,
        }
    }

    /// Returns `true` if all probabilities are zero — used to skip the layer
    /// entirely in the hot path.
    pub fn is_noop(&self) -> bool {
        self.delay_p == 0.0 && self.drop_p == 0.0
    }
}

// ── Layer ─────────────────────────────────────────────────────────────────────

/// Tower [`Layer`] that wraps a service with chaos injection.
#[derive(Debug, Clone)]
pub struct ChaosLayer {
    config: ChaosConfig,
}

impl ChaosLayer {
    pub fn from_env() -> Self {
        let config = ChaosConfig::from_env();
        if !config.is_noop() {
            tracing::info!(
                delay_p = config.delay_p,
                drop_p  = config.drop_p,
                "chaos.middleware.active"
            );
        }
        Self { config }
    }

    pub fn with_config(config: ChaosConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for ChaosLayer {
    type Service = ChaosMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ChaosMiddleware {
            inner,
            config: self.config,
        }
    }
}

// ── Middleware ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ChaosMiddleware<S> {
    inner:  S,
    config: ChaosConfig,
}

impl<S, ReqBody> Service<Request<ReqBody>> for ChaosMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Body>;
    type Error    = S::Error;
    type Future   = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Fast path — no chaos configured.
        if self.config.is_noop() {
            return Box::pin(self.inner.call(req));
        }

        let config = self.config;
        let mut inner = self.inner.clone();
        // We need to call the *original* inner, not the clone, for poll_ready
        // correctness — swap them.
        std::mem::swap(&mut self.inner, &mut inner);

        Box::pin(async move {
            // Compute all random values up front and drop `rng` before any
            // await point — ThreadRng is not Send so it cannot be held across
            // an await boundary.
            let (should_drop, should_delay, delay_ms) = {
                let mut rng = rand::thread_rng();
                let should_drop  = rng.gen::<f64>() < config.drop_p;
                let should_delay = rng.gen::<f64>() < config.delay_p;
                let delay_ms     = rng.gen_range(config.delay_min_ms..=config.delay_max_ms);
                (should_drop, should_delay, delay_ms)
                // rng dropped here — before any await
            };

            // ── Drop fault ────────────────────────────────────────────────────
            if should_drop {
                warn!(
                    chaos.injected = true,
                    chaos.type     = "drop",
                    "chaos.drop"
                );
                let response = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from(r#"{"error":"CHAOS_DROP","message":"chaos fault injected"}"#))
                    .unwrap();
                return Ok(response);
            }

            // ── Delay fault ───────────────────────────────────────────────────
            if should_delay {
                warn!(
                    chaos.injected = true,
                    chaos.type     = "delay",
                    delay_ms       = delay_ms,
                    "chaos.delay"
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            inner.call(req).await
        })
    }
}
