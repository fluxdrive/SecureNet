//! Vault Service — the trust anchor for the whole system.
//!
//! ## Startup sequence
//!
//! 1. Initialise telemetry
//! 2. Check Secure Boot state
//! 3. Load CA cert + key from environment / mounted files
//! 4. Initialise Issuer, IssuanceLog, Allowlist
//! 5. Bind HTTP server and serve routes
//!
//! ## Environment variables
//!
//! | Variable          | Default                        | Description               |
//! |-------------------|--------------------------------|---------------------------|
//! | `CA_CERT_PATH`    | `bootstrap/ca.pem`             | Root CA certificate (PEM) |
//! | `CA_KEY_PATH`     | `bootstrap/ca-key.pem`         | Root CA private key (PEM) |
//! | `ALLOWLIST_PATH`  | `allowlist.toml`               | Permitted machine IDs     |
//! | `LOG_PATH`        | `/var/log/vault/issuance.log`  | Issuance log file         |
//! | `PORT`            | `8003`                         | Listen port               |
//! | `JAEGER_ENDPOINT` | _(none — tracing to stdout)_   | OTLP gRPC endpoint        |

mod attestation_verifier;
mod issuer;
mod log;
mod routes;
mod state;

use anyhow::{Context, Result};
use axum::{routing::{get, post}, Router};
use tracing::info;

use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Telemetry ──────────────────────────────────────────────────────────
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("vault-service", jaeger.as_deref())?;

    info!("vault-service starting");

    // ── 2. Secure Boot check ──────────────────────────────────────────────────
    let sb = shared::attestation::check_secure_boot();
    info!(secure_boot = %sb, "boot.secure_boot_checked");

    // ── 3. Load CA material ───────────────────────────────────────────────────
    let ca_cert_path = std::env::var("CA_CERT_PATH")
        .unwrap_or_else(|_| "bootstrap/ca.pem".into());
    let ca_key_path  = std::env::var("CA_KEY_PATH")
        .unwrap_or_else(|_| "bootstrap/ca-key.pem".into());

    let ca_cert_pem = std::fs::read_to_string(&ca_cert_path)
        .with_context(|| format!("cannot read CA cert from {ca_cert_path}"))?;
    let ca_key_pem  = std::fs::read_to_string(&ca_key_path)
        .with_context(|| format!("cannot read CA key from {ca_key_path}"))?;

    info!(ca_cert_path, ca_key_path, "vault.ca_material_loaded");

    // ── 4. Load allowlist ─────────────────────────────────────────────────────
    let allowlist_path = std::env::var("ALLOWLIST_PATH")
        .unwrap_or_else(|_| "allowlist.toml".into());

    let allowlist_toml = std::fs::read_to_string(&allowlist_path)
        .with_context(|| format!("cannot read allowlist from {allowlist_path}"))?;

    let allowlist = attestation_verifier::Allowlist::from_toml(&allowlist_toml)
        .context("failed to parse allowlist.toml")?;

    info!(
        path           = allowlist_path,
        machine_count  = allowlist.machine_ids.len(),
        "vault.allowlist_loaded"
    );

    // ── 5. Initialise components ──────────────────────────────────────────────
    let issuer_instance = issuer::Issuer::from_pem(&ca_cert_pem, &ca_key_pem)
        .context("failed to initialise issuer")?;

    let log_path = std::env::var("LOG_PATH")
        .unwrap_or_else(|_| "/var/log/vault/issuance.log".into());

    let log_instance = log::IssuanceLog::open(log_path);

    let app_state = AppState::new(issuer_instance, log_instance, allowlist);

    // ── 6. Router ─────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/vault/nonce",  get(routes::nonce))
        .route("/vault/unseal", post(routes::unseal))
        .route("/vault/renew",  post(routes::renew))
        .route("/vault/revoke", post(routes::revoke))
        .route("/vault/crl",    get(routes::crl))
        .route("/vault/health", get(routes::health))
        .with_state(app_state);

    // ── 7. Bind and serve ─────────────────────────────────────────────────────
    let port = std::env::var("PORT").unwrap_or_else(|_| "8003".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;

    info!(%addr, "vault-service ready");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}
