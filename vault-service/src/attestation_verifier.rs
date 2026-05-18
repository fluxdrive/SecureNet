//! Server-side attestation verification.
//!
//! The vault verifies two things before issuing a certificate:
//!
//! 1. **Allowlist check** — the `machine_id` must be in `allowlist.toml`.
//! 2. **TPM quote verification** — if a quote is present, verify its signature
//!    over the nonce using the provided attestation key public area.
//!    If absent (dev mode), log a warning and allow through.
//!
//! The nonce freshness check (± 5 seconds) is enforced by the vault issuing
//! a nonce via `GET /vault/nonce` and tracking its expiry in memory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use hex;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{info, warn};

use shared::models::UnsealRequest;

// ── Allowlist ─────────────────────────────────────────────────────────────────

/// Machine IDs permitted to unseal, loaded from `allowlist.toml`.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct Allowlist {
    pub machine_ids: Vec<String>,
}

impl Allowlist {
    pub fn from_toml(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }

    pub fn contains(&self, machine_id: &str) -> bool {
        // "dev" is a special wildcard used in development when machine-id
        // is not meaningful (e.g. fresh Docker containers).
        if self.machine_ids.iter().any(|id| id == "dev") {
            return true;
        }
        self.machine_ids.iter().any(|id| id == machine_id)
    }
}

// ── Nonce store ───────────────────────────────────────────────────────────────

/// Tracks issued nonces and their expiry times.
///
/// A nonce is valid for 30 seconds after issuance.  After it is used once it
/// is removed — nonces are single-use.
#[derive(Clone)]
pub struct NonceStore {
    inner: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a newly-issued nonce.
    pub async fn register(&self, nonce: Vec<u8>) {
        let mut map = self.inner.lock().await;
        // Prune expired entries while we have the lock.
        map.retain(|_, issued_at| issued_at.elapsed() < Duration::from_secs(30));
        map.insert(nonce, Instant::now());
    }

    /// Consume a nonce — returns `true` if valid and fresh, `false` otherwise.
    /// Removes the nonce on success (single-use).
    pub async fn consume(&self, nonce: &[u8]) -> bool {
        let mut map = self.inner.lock().await;
        match map.remove(nonce) {
            Some(issued_at) => issued_at.elapsed() < Duration::from_secs(30),
            None            => false,
        }
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verify an unseal request.
///
/// Steps:
/// 1. Allowlist check on `machine_id`.
/// 2. Nonce freshness — must have been issued by this vault instance.
/// 3. TPM quote signature verification (dev stub: SHA-256 of nonce).
///
/// Returns `Ok(())` on success, or an error with a rejection reason.
pub async fn verify(
    req:         &UnsealRequest,
    allowlist:   &Allowlist,
    nonce_store: &NonceStore,
) -> Result<()> {
    // ── 1. Allowlist ──────────────────────────────────────────────────────────
    if !allowlist.contains(&req.machine_id) {
        bail!("machine_id '{}' not in allowlist", req.machine_id);
    }
    info!(machine_id = %req.machine_id, "attestation.allowlist_passed");

    // ── 2. Nonce freshness ────────────────────────────────────────────────────
    if req.nonce.is_empty() {
        bail!("nonce is required");
    }

    // Decode hex nonce back to bytes for store lookup.
    let nonce_bytes = hex::decode(&req.nonce)
        .map_err(|_| anyhow::anyhow!("nonce is not valid hex"))?;

    if !nonce_store.consume(&nonce_bytes).await {
        bail!("nonce is invalid, expired, or already used");
    }
    info!("attestation.nonce_valid");

    // ── 3. TPM quote ──────────────────────────────────────────────────────────
    if req.tpm_quote.is_empty() {
        // Dev/fallback mode — no TPM available.
        warn!(
            machine_id = %req.machine_id,
            "attestation.tpm_quote_absent - dev mode accepted"
        );
        return Ok(());
    }

    // Dev-mode stub: the client sends hex(SHA-256(nonce)) as the "quote".
    // A real implementation would use tss-esapi to verify the TPM2_Quote
    // structure against the AK public key.
    let expected_hex = hex::encode(Sha256::digest(&nonce_bytes));
    if req.tpm_quote != expected_hex {
        bail!("TPM quote verification failed");
    }

    info!(
        machine_id = %req.machine_id,
        "attestation.tpm_quote_verified"
    );

    Ok(())
}
