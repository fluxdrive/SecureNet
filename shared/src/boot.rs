//! Service boot sequence — shared by all three application services.
//!
//! Every service goes through the same boot sequence:
//!
//! ```text
//! init_telemetry()
//!     → check_secure_boot()
//!     → unseal(vault_url)          — proves hardware identity, gets cert
//!     → RotatingTlsConfig::new()   — loads cert into RwLock
//!     → spawn_rotation_task()      — background renewal loop
//!     → build_mtls_server()        — rustls acceptor ready to bind
//! ```
//!
//! The returned `BootResult` contains everything needed to bind the server
//! and answer health checks.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use crate::{
    identity::ServiceIdentity,
    models::CertBundle,
    rotation::RotatingTlsConfig,
    tls,
    vault_client::HttpVaultClient,
};

// ── BootResult ────────────────────────────────────────────────────────────────

/// Everything a service needs after a successful boot sequence.
pub struct BootResult {
    /// The initial cert bundle — used to build mTLS reqwest clients.
    pub bundle:     CertBundle,
    /// Rotating TLS config — pass to axum-server's TLS acceptor.
    pub tls_config: RotatingTlsConfig,
    /// The vault client — kept alive so the rotation task can use it.
    pub vault:      Arc<HttpVaultClient>,
    /// The service identity — used for health endpoint sealed/unsealed status.
    pub identity:   ServiceIdentity,
}

// ── Boot sequence ─────────────────────────────────────────────────────────────

/// Run the full boot sequence for an application service.
///
/// # Arguments
///
/// * `service_name` — e.g. `"user-service"`
/// * `vault_url`    — e.g. `"http://localhost:8003"` (plain HTTP for initial unseal)
///
/// # Errors
///
/// Returns an error if:
/// - The vault is unreachable
/// - The vault rejects the attestation
/// - The cert bundle cannot be loaded into rustls
///
/// Callers should treat any error as fatal and exit — the supervisor will
/// restart the process.
pub async fn run(service_name: &str, vault_url: &str) -> Result<BootResult> {
    // Install the ring crypto provider for rustls.
    // Must happen before any TLS operations.  Safe to call multiple times —
    // subsequent calls are ignored if a provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── 1. Unseal ─────────────────────────────────────────────────────────────
    let identity  = ServiceIdentity::new(service_name);
    let http      = reqwest::Client::new();

    let bundle = identity
        .unseal(vault_url, &http)
        .await
        .with_context(|| format!("failed to unseal with vault at {vault_url}"))?;

    info!(
        serial     = %bundle.serial,
        expires_at = %bundle.expires_at,
        "boot.unsealed"
    );

    // ── 2. Build rotating TLS config ─────────────────────────────────────────
    let tls_config = RotatingTlsConfig::new(&bundle)
        .context("failed to build TLS config from cert bundle")?;

    // ── 3. Spawn rotation background task ────────────────────────────────────
    let vault = Arc::new(HttpVaultClient::new(
        vault_url,
        service_name,
        bundle.clone(),
    ));

    let initial_ttl = bundle.ttl_secs();
    tls_config.spawn_rotation_task(
        vault.clone(),
        service_name.to_string(),
        initial_ttl,
    );

    info!(initial_ttl, "boot.rotation_task_spawned");

    Ok(BootResult {
        bundle,
        tls_config,
        vault,
        identity,
    })
}

/// Run the boot sequence for the API gateway.
///
/// Same as `run()` but uses `RotatingTlsConfig::new_gateway()` so the
/// inbound server does not require client certificates from external callers.
pub async fn run_gateway(service_name: &str, vault_url: &str) -> Result<BootResult> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let identity = ServiceIdentity::new(service_name);
    let http     = reqwest::Client::new();

    let bundle = identity
        .unseal(vault_url, &http)
        .await
        .with_context(|| format!("failed to unseal with vault at {vault_url}"))?;

    info!(serial = %bundle.serial, expires_at = %bundle.expires_at, "boot.unsealed");

    // Gateway uses TLS-only server config — no client cert required inbound
    let tls_config = RotatingTlsConfig::new_gateway(&bundle)
        .context("failed to build gateway TLS config")?;

    let vault = Arc::new(HttpVaultClient::new(
        vault_url,
        service_name,
        bundle.clone(),
    ));

    let initial_ttl = bundle.ttl_secs();
    tls_config.spawn_rotation_task(
        vault.clone(),
        service_name.to_string(),
        initial_ttl,
    );

    info!(initial_ttl, "boot.rotation_task_spawned");

    Ok(BootResult { bundle, tls_config, vault, identity })
}

/// Build a reqwest client for outbound mTLS calls.
///
/// Uses `use_preconfigured_tls` with a rustls `ClientConfig` that:
/// - Only trusts our private CA (not system roots)
/// - Presents the service cert as client identity on every connection
pub fn mtls_client(bundle: &CertBundle) -> Result<reqwest::Client> {
    let client_config = tls::client_config(bundle)
        .context("failed to build rustls ClientConfig")?;

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .build()
        .context("failed to build mTLS reqwest client")?;

    Ok(client)
}
