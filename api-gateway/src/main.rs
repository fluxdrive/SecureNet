//! API Gateway — external-facing service.
//!
//! Responsibilities:
//! - Issue and validate JWTs (RS256) on the `/auth/*` routes
//! - Forward authenticated requests to user-service and order-service over mTLS
//! - Inject W3C `traceparent` headers on all outbound calls
//! - Optionally inject chaos faults (when `CHAOS_*` env vars are set)
//!
//! ## Boot sequence
//!
//! 1. Initialise telemetry (tracing → Jaeger)
//! 2. Check Secure Boot state (informational)
//! 3. Unseal: POST /vault/unseal with TPM quote → receive CertBundle
//! 4. Build RotatingTlsConfig from CertBundle
//! 5. Spawn cert rotation background task
//! 6. Bind axum-server with mTLS ServerConfig
//! 7. Signal systemd READY=1

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Telemetry ──────────────────────────────────────────────────────────
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("api-gateway", jaeger.as_deref())?;

    info!("api-gateway starting");

    // ── 2. Secure Boot check ──────────────────────────────────────────────────
    let sb_state = shared::attestation::check_secure_boot();
    info!(secure_boot = %sb_state, "boot.secure_boot_checked");

    // ── 3–5. Vault unseal + cert rotation ─────────────────────────────────────
    // TODO(phase-2): implement vault client and call identity.unseal()
    // TODO(phase-2): build RotatingTlsConfig and spawn rotation task

    // ── 6. Routes ─────────────────────────────────────────────────────────────
    // TODO(phase-3): mount jwt middleware + proxy routes

    // ── 7. Bind server ────────────────────────────────────────────────────────
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;
    info!(%addr, "api-gateway listening (plaintext stub — mTLS in phase 2)");

    // Stub: plain HTTP server so we can verify the binary runs.
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status":  "ok",
        "service": "api-gateway",
        "sealed":  true,          // will be false after phase-2
    }))
}
