//! Order Service — internal service, mTLS only.
//!
//! Responsibilities:
//! - Serve `GET /orders/:id` returning `OrderWithUser` JSON
//! - Call user-service over mTLS to resolve the user on each order
//! - Propagate W3C `traceparent` header on the outbound user-service call

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("order-service", jaeger.as_deref())?;

    info!("order-service starting");

    let sb_state = shared::attestation::check_secure_boot();
    info!(secure_boot = %sb_state, "boot.secure_boot_checked");

    // TODO(phase-2): vault unseal + RotatingTlsConfig
    // TODO(phase-3): mount /orders/:id route + mTLS reqwest client to user-service

    let port = std::env::var("PORT").unwrap_or_else(|_| "8002".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;
    info!(%addr, "order-service listening (plaintext stub)");

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
        "service": "order-service",
        "sealed":  true,
    }))
}
