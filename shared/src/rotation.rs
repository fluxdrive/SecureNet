//! Hot certificate rotation without downtime.
//!
//! `RotatingTlsConfig` wraps a `rustls::ServerConfig` behind an
//! `Arc<RwLock<...>>`.  A background tokio task fetches a fresh cert from the
//! vault at 90 % of the current TTL and atomically swaps it in.
//!
//! ## Why this is safe
//!
//! - In-flight TLS handshakes hold a clone of the *old* `Arc<ServerConfig>`.
//!   They complete normally on the old cert.
//! - New connections — even those arriving in the same millisecond as the swap
//!   — will see the new cert.
//! - The write lock is held only for the pointer swap (nanoseconds), not
//!   during the network round-trip to the vault.

use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use crate::{
    errors::AppError,
    models::CertBundle,
    tls,
};

// ── VaultClient trait ─────────────────────────────────────────────────────────

/// Abstraction over the vault HTTP client.
///
/// The real implementation lives in each service binary; a mock can be used in
/// tests by implementing this trait.
#[async_trait::async_trait]
pub trait VaultClient: Send + Sync + 'static {
    /// Fetch a fresh `CertBundle` from the vault, presenting the current cert
    /// as the mTLS client identity.
    async fn renew(&self, service_name: &str) -> Result<CertBundle, AppError>;
}

// ── RotatingTlsConfig ─────────────────────────────────────────────────────────

/// A `ServerConfig` that can be atomically replaced without restarting.
///
/// Pass the inner `Arc<RwLock<Arc<ServerConfig>>>` to `axum_server`'s TLS
/// acceptor; it reads the current value on every new connection.
#[derive(Clone)]
pub struct RotatingTlsConfig {
    /// The currently-active TLS configuration.
    pub inner:      Arc<RwLock<Arc<ServerConfig>>>,
    /// Serial number of the currently-active cert (for health endpoint).
    pub serial:     Arc<RwLock<String>>,
    /// Whether this is a gateway config (no client cert required on inbound).
    is_gateway:     bool,
}

impl RotatingTlsConfig {
    /// Create a new `RotatingTlsConfig` from an initial `CertBundle`.
    /// Uses full mTLS — requires client certificates (internal services).
    pub fn new(bundle: &CertBundle) -> Result<Self, AppError> {
        let config = Arc::new(tls::server_config(bundle)?);
        Ok(Self {
            inner:      Arc::new(RwLock::new(config)),
            serial:     Arc::new(RwLock::new(bundle.serial.clone())),
            is_gateway: false,
        })
    }

    /// Create a `RotatingTlsConfig` for the gateway — TLS only, no client cert.
    /// External clients authenticate via JWT instead of mTLS.
    pub fn new_gateway(bundle: &CertBundle) -> Result<Self, AppError> {
        let config = Arc::new(tls::gateway_server_config(bundle)?);
        Ok(Self {
            inner:      Arc::new(RwLock::new(config)),
            serial:     Arc::new(RwLock::new(bundle.serial.clone())),
            is_gateway: true,
        })
    }

    /// Read the currently-active `ServerConfig`.
    pub async fn current(&self) -> Arc<ServerConfig> {
        self.inner.read().await.clone()
    }

    /// Read the serial number of the currently-active cert.
    pub async fn current_serial(&self) -> String {
        self.serial.read().await.clone()
    }

    /// Spawn a background task that renews the cert before it expires.
    ///
    /// The task:
    /// 1. Sleeps until 90 % of the current TTL has elapsed.
    /// 2. Calls `vault.renew()` (with retries on failure).
    /// 3. Swaps the inner `Arc<ServerConfig>` atomically.
    /// 4. Emits structured log events for every step.
    /// 5. Loops — the next sleep is calculated from the *new* cert's TTL.
    pub fn spawn_rotation_task<V: VaultClient>(
        &self,
        vault:        Arc<V>,
        service_name: String,
        initial_ttl:  u64,
    ) {
        let inner      = self.inner.clone();
        let serial     = self.serial.clone();
        let is_gateway = self.is_gateway;

        tokio::spawn(async move {
            rotation_loop(vault, service_name, inner, serial, initial_ttl, is_gateway).await;
        });
    }
}

// ── Background rotation loop ──────────────────────────────────────────────────

/// The long-running rotation task.  Never returns under normal operation.
#[instrument(skip(vault, inner, serial))]
async fn rotation_loop<V: VaultClient>(
    vault:        Arc<V>,
    service_name: String,
    inner:        Arc<RwLock<Arc<ServerConfig>>>,
    serial:       Arc<RwLock<String>>,
    initial_ttl:  u64,
    is_gateway:   bool,
) {
    let mut ttl = initial_ttl;

    loop {
        // Sleep until 90 % of the TTL has elapsed.
        let sleep_secs = (ttl as f64 * 0.9) as u64;
        info!(
            ttl_secs   = ttl,
            sleep_secs = sleep_secs,
            "cert.rotation.scheduled"
        );
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

        // Attempt renewal with up to 3 retries.
        let new_bundle = retry_renew(&vault, &service_name, 3).await;

        match new_bundle {
            Ok(bundle) => {
                let new_serial = bundle.serial.clone();
                let new_ttl    = bundle.ttl_secs();

                let config_result = if is_gateway {
                    tls::gateway_server_config(&bundle)
                } else {
                    tls::server_config(&bundle)
                };
                match config_result {
                    Ok(config) => {
                        // ── Atomic swap ───────────────────────────────────────
                        *inner.write().await  = Arc::new(config);
                        *serial.write().await = new_serial.clone();
                        // ─────────────────────────────────────────────────────

                        info!(
                            new_serial = %new_serial,
                            new_ttl    = new_ttl,
                            "cert.rotation.succeeded"
                        );

                        ttl = new_ttl;
                    }
                    Err(e) => {
                        error!(error = %e, "cert.rotation.failed - bad cert from vault");
                        // Keep the existing cert; retry on the next cycle.
                        ttl = 30; // back-off: retry in 30 s
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "cert.rotation.failed - vault unreachable after retries");
                // If we can't renew, try again soon — don't wait the full TTL.
                ttl = 30;
            }
        }
    }
}

/// Attempt `vault.renew()` up to `max_attempts` times with exponential back-off.
async fn retry_renew<V: VaultClient>(
    vault:        &Arc<V>,
    service_name: &str,
    max_attempts: u32,
) -> Result<CertBundle, AppError> {
    let mut delay = Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        info!(attempt, "cert.rotation.started");

        match vault.renew(service_name).await {
            Ok(bundle) => return Ok(bundle),
            Err(e) => {
                warn!(attempt, error = %e, "cert.rotation.attempt_failed");
                if attempt < max_attempts {
                    tokio::time::sleep(delay).await;
                    delay *= 2; // exponential back-off
                }
            }
        }
    }

    Err(AppError::VaultUnreachable(format!(
        "cert renewal failed after {max_attempts} attempts"
    )))
}
