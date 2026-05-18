//! Boot-time identity management.
//!
//! Every service starts in the `Locked` state and cannot serve requests until
//! it has successfully obtained a certificate from the vault.  This module
//! enforces that state machine.
//!
//! ## State diagram
//!
//! ```text
//! ┌────────┐  unseal() called  ┌──────────┐  vault responds OK  ┌─────────┐
//! │ Locked │──────────────────►│ Unsealing│────────────────────►│ Serving │
//! └────────┘                   └──────────┘                     └─────────┘
//!                                    │
//!                                    │ vault rejects / timeout
//!                                    ▼
//!                               process exits (systemd restarts)
//! ```
//!
//! `Serving` is the only state in which handlers will accept connections.
//! Kubernetes' readiness probe calls `GET /health` which checks this.

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use hex;
use crate::{
    attestation,
    errors::AppError,
    models::{CertBundle, UnsealRequest, UnsealResponse},
};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Initial state — no cert, no network listeners.
    Locked,
    /// Vault request in flight.
    Unsealing,
    /// Cert obtained, mTLS listeners are bound.
    Serving,
}

// ── ServiceIdentity ───────────────────────────────────────────────────────────

/// Holds the service's current state and cert bundle.
///
/// Cloning is cheap — all fields are behind `Arc`.
#[derive(Clone)]
pub struct ServiceIdentity {
    state:        Arc<RwLock<ServiceState>>,
    bundle:       Arc<RwLock<Option<CertBundle>>>,
    service_name: String,
}

impl std::fmt::Debug for ServiceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceIdentity")
            .field("service_name", &self.service_name)
            .finish()
    }
}

impl ServiceIdentity {
    /// Create a new identity in the `Locked` state.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            state:        Arc::new(RwLock::new(ServiceState::Locked)),
            bundle:       Arc::new(RwLock::new(None)),
            service_name: service_name.into(),
        }
    }

    /// Returns `true` if the service has completed unsealing and is ready to
    /// serve requests.
    pub async fn is_serving(&self) -> bool {
        *self.state.read().await == ServiceState::Serving
    }

    /// Returns a clone of the current `CertBundle`, or `None` if still locked.
    pub async fn bundle(&self) -> Option<CertBundle> {
        self.bundle.read().await.clone()
    }

    /// Attempt to unseal by contacting the vault.
    ///
    /// This is called once during service startup.  On success the state
    /// transitions to `Serving` and the returned `CertBundle` is ready for use.
    /// On failure the process should exit so the supervisor can restart it.
    ///
    /// # Arguments
    ///
    /// * `vault_url` — Base URL of the vault service, e.g. `https://vault:8003`
    /// * `http`      — A plain (non-mTLS) reqwest client used *only* for the
    ///                 initial unseal.  Subsequent vault calls use mTLS.
    #[instrument(skip(http), fields(service = %self.service_name))]
    pub async fn unseal(
        &self,
        vault_url: &str,
        http:      &reqwest::Client,
    ) -> Result<CertBundle, AppError> {
        // Transition: Locked → Unsealing
        *self.state.write().await = ServiceState::Unsealing;
        info!("vault.unseal.attempt");

        // Gather attestation material.
        let machine_id = attestation::machine_id()
            .unwrap_or_else(|_| "unknown".into());

        // Fetch nonce from vault — the vault registers it in its NonceStore.
        // We must use the vault's nonce, not a locally-generated one, because
        // the vault verifies the nonce was issued by itself before accepting it.
        let nonce_hex = fetch_nonce(vault_url, http).await?;
        let nonce_bytes = hex::decode(&nonce_hex)
            .map_err(|e| AppError::VaultUnreachable(format!("bad nonce hex: {e}")))?;

        let (tpm_quote_hex, ak_pub_hex) = match attestation::generate_quote(&nonce_bytes).await {
            Ok((quote, ak)) => {
                info!("tpm.quote.generated");
                (hex::encode(quote), hex::encode(ak))
            }
            Err(e) => {
                warn!(error = %e, "tpm.quote.failed - falling back to machine-id only");
                (String::new(), String::new())
            }
        };

        // Build and send the unseal request.
        let req = UnsealRequest {
            service_name: self.service_name.clone(),
            machine_id:   machine_id.clone(),
            tpm_quote:    tpm_quote_hex,
            nonce:        nonce_hex,
            ak_pub:       ak_pub_hex,
        };

        let url      = format!("{vault_url}/vault/unseal");
        let response = http
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body   = response.text().await.unwrap_or_default();
            error!(
                status = %status,
                body   = %body,
                "vault.unseal.rejected"
            );
            // Transition back to Locked (caller should exit)
            *self.state.write().await = ServiceState::Locked;
            return Err(AppError::VaultRejected(body));
        }

        let resp: UnsealResponse = response
            .json()
            .await
            .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

        let bundle = resp.bundle;

        // Transition: Unsealing → Serving
        *self.bundle.write().await = Some(bundle.clone());
        *self.state.write().await  = ServiceState::Serving;

        info!(
            serial     = %bundle.serial,
            expires_at = %bundle.expires_at,
            machine_id = %machine_id,
            "vault.unseal.granted"
        );

        Ok(bundle)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Fetch a fresh nonce from the vault's GET /vault/nonce endpoint.
///
/// The vault registers the nonce in its NonceStore.  We must use this nonce
/// rather than generating one locally — the vault will reject any nonce it
/// didn't issue itself.
async fn fetch_nonce(
    vault_url: &str,
    http:      &reqwest::Client,
) -> Result<String, AppError> {
    let url  = format!("{vault_url}/vault/nonce");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

    body["nonce"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::VaultUnreachable("nonce field missing in vault response".into()))
}