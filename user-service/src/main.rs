//! User Service — internal service, mTLS only.
//!
//! Responsibilities:
//! - Serve `GET /users/:id` returning `User` JSON
//! - Expose `GET /health` for Kubernetes probes
//!
//! Accepts connections only from peers presenting a cert signed by the shared CA.

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("user-service", jaeger.as_deref())?;

    info!("user-service starting");

    let sb_state = shared::attestation::check_secure_boot();
    info!(secure_boot = %sb_state, "boot.secure_boot_checked");

    // TODO(phase-2): vault unseal + RotatingTlsConfig
    // TODO(phase-3): mount /users/:id route

    let port = std::env::var("PORT").unwrap_or_else(|_| "8001".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;
    info!(%addr, "user-service listening (plaintext stub)");

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
        "service": "user-service",
        "sealed":  true,
    }))
}
