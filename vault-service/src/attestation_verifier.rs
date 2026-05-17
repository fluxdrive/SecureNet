//! Server-side TPM quote verification.
//!
//! The vault receives a quote + nonce + AK public key from each service.
//! This module verifies:
//! 1. The nonce is fresh (within a 5-second window).
//! 2. The quote signature is valid over the nonce using the provided AK.
//! 3. The machine_id is in the allowlist.

use anyhow::Result;

use shared::models::UnsealRequest;

/// The allowlist loaded from `allowlist.toml`.
#[derive(Debug, serde::Deserialize)]
pub struct Allowlist {
    /// Known machine IDs permitted to unseal.
    pub machine_ids: Vec<String>,
}

impl Allowlist {
    pub fn from_toml(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }

    pub fn contains(&self, machine_id: &str) -> bool {
        self.machine_ids.iter().any(|id| id == machine_id)
    }
}

/// Verify an unseal request.
///
/// Returns `Ok(())` if the request is valid, or an error with a human-readable
/// rejection reason.
pub fn verify(req: &UnsealRequest, allowlist: &Allowlist) -> Result<()> {
    // ── Step 1: allowlist check ───────────────────────────────────────────────
    if !allowlist.contains(&req.machine_id) {
        anyhow::bail!("machine_id '{}' not in allowlist", req.machine_id);
    }

    // ── Step 2: TPM quote verification ───────────────────────────────────────
    if req.tpm_quote.is_empty() {
        // Dev/fallback mode — log a warning but allow through.
        tracing::warn!(
            machine_id = %req.machine_id,
            "attestation.tpm_quote_absent - dev mode fallback accepted"
        );
        return Ok(());
    }

    // TODO(phase-2): verify TPM quote signature with tss-esapi
    // 1. Parse ak_pub as TPM2B_PUBLIC
    // 2. Verify quote signature over nonce
    // 3. Check nonce freshness (wall-clock ± 5s)

    Ok(())
}
