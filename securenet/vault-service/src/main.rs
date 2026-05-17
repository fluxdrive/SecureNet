//! Vault Service — the trust anchor for the whole system.
//!
//! Responsibilities:
//! - Verify TPM quotes / machine-id against allowlist
//! - Sign and issue short-lived x509 certificates (5-minute TTL)
//! - Maintain an append-only issuance log
//! - Serve `POST /vault/unseal`, `POST /vault/renew`, `GET /vault/health`
//!
//! The vault itself uses a long-lived bootstrap certificate (baked into the
//! image at build time).  Everything else is dynamically issued.

mod issuer;
mod attestation_verifier;
mod log;
mod routes;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("vault-service", jaeger.as_deref())?;

    info!("vault-service starting");

    // Vault checks its own Secure Boot state too — if the trust anchor is
    // running on an unverified boot chain, the whole system's security
    // guarantee is weakened.
    let sb_state = shared::attestation::check_secure_boot();
    info!(secure_boot = %sb_state, "boot.secure_boot_checked");

    // TODO(phase-2): load bootstrap cert + CA key from env / mounted Secret
    // TODO(phase-2): initialise issuer::Issuer
    // TODO(phase-2): initialise log::IssuanceLog
    // TODO(phase-2): mount routes

    let port = std::env::var("PORT").unwrap_or_else(|_| "8003".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;
    info!(%addr, "vault-service listening (plaintext stub)");

    let app = axum::Router::new()
        .route("/vault/health", axum::routing::get(health));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status":  "ok",
        "service": "vault-service",
    }))
}
