//! HTTP client for the vault service.
//!
//! `HttpVaultClient` implements `VaultClient` from `rotation.rs` and is used
//! by the cert rotation background task to renew certs before they expire.
//!
//! ## Two clients
//!
//! - **Plain HTTP client** — used only for the initial unseal request.
//!   The service has no cert yet so mTLS is not possible.
//! - **mTLS client** — built from the initial `CertBundle` and used for all
//!   subsequent vault calls (renewal).  Presents the service cert to the vault.

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::{
    attestation,
    errors::AppError,
    models::{CertBundle, UnsealRequest, UnsealResponse},
    rotation::VaultClient,
};

// ── HttpVaultClient ───────────────────────────────────────────────────────────

/// A vault client that re-attests on every renewal call.
///
/// In Phase 3 (plain HTTP), renewal goes through the same `/vault/renew`
/// endpoint as unseal — the service re-proves its identity each time.
/// In a future phase this will use the mTLS cert for authentication instead.
#[derive(Clone)]
pub struct HttpVaultClient {
    vault_url:    String,
    service_name: String,
    /// Plain HTTP client — used for all vault calls until mTLS is wired.
    http:         reqwest::Client,
    /// Current bundle — updated after each successful renewal.
    bundle:       Arc<RwLock<Option<CertBundle>>>,
}

impl HttpVaultClient {
    /// Create a new client.
    ///
    /// `bundle` should be the `CertBundle` received from the initial unseal —
    /// it will be presented on renewal calls once mTLS is wired in Phase 4.
    pub fn new(
        vault_url:    impl Into<String>,
        service_name: impl Into<String>,
        initial_bundle: CertBundle,
    ) -> Self {
        Self {
            vault_url:    vault_url.into(),
            service_name: service_name.into(),
            http:         reqwest::Client::new(),
            bundle:       Arc::new(RwLock::new(Some(initial_bundle))),
        }
    }

    /// Fetch a fresh nonce from the vault.
    async fn fetch_nonce(&self) -> Result<String, AppError> {
        let url = format!("{}/vault/nonce", self.vault_url);
        let resp = self.http
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
            .ok_or_else(|| AppError::VaultUnreachable("nonce field missing".into()))
    }
}

#[async_trait::async_trait]
impl VaultClient for HttpVaultClient {
    #[instrument(skip(self), fields(service = %self.service_name))]
    async fn renew(&self, service_name: &str) -> Result<CertBundle, AppError> {
        info!("vault_client.renew.starting");

        // Get a fresh nonce.
        let nonce_hex = self.fetch_nonce().await?;
        let nonce_bytes = hex::decode(&nonce_hex)
            .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

        // Generate TPM quote over the nonce.
        let machine_id = attestation::machine_id()
            .unwrap_or_else(|_| "unknown".into());

        let (tpm_quote_hex, ak_pub_hex) =
            match attestation::generate_quote(&nonce_bytes).await {
                Ok((q, ak)) => (hex::encode(q), hex::encode(ak)),
                Err(_)      => (String::new(), String::new()),
            };

        let req = UnsealRequest {
            service_name: service_name.to_string(),
            machine_id,
            tpm_quote: tpm_quote_hex,
            nonce:     nonce_hex,
            ak_pub:    ak_pub_hex,
        };

        let url  = format!("{}/vault/renew", self.vault_url);
        let resp = self.http
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::VaultRejected(body));
        }

        let unseal_resp: UnsealResponse = resp
            .json()
            .await
            .map_err(|e| AppError::VaultUnreachable(e.to_string()))?;

        let bundle = unseal_resp.bundle;

        // Update stored bundle for future mTLS use.
        *self.bundle.write().await = Some(bundle.clone());

        info!(serial = %bundle.serial, "vault_client.renew.succeeded");
        Ok(bundle)
    }
}
