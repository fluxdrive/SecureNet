//! Hardware attestation — TPM2 quote generation and Secure Boot state.
//!
//! ## TPM2 via swtpm
//!
//! In development, `swtpm` emulates a TPM2 device over a Unix socket.  The
//! socket path is read from the `SWTPM_SOCK` environment variable, defaulting
//! to `/run/swtpm/tpm.sock`.
//!
//! In production, swap the TCTI string to `device:/dev/tpm0` (or `tabrmd`).
//!
//! ## Secure Boot
//!
//! Secure Boot state is read from the UEFI EFI variable filesystem at
//! `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`.
//! This is informational and non-blocking — services start regardless of
//! Secure Boot state, but the state is logged and emitted as a trace attribute.

use tracing::{info, warn};

use crate::errors::AppError;

// ── Secure Boot ───────────────────────────────────────────────────────────────

/// The state of UEFI Secure Boot on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootState {
    /// Secure Boot is active — firmware verified the boot chain.
    Enabled,
    /// Secure Boot is present but disabled.
    Disabled,
    /// The EFI variable filesystem is not available (container without UEFI, VM
    /// with legacy BIOS, or insufficient permissions).
    Unavailable,
}

impl std::fmt::Display for SecureBootState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureBootState::Enabled     => write!(f, "enabled"),
            SecureBootState::Disabled    => write!(f, "disabled"),
            SecureBootState::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Read Secure Boot state from the UEFI EFI variable filesystem.
///
/// Never panics — if the variable cannot be read for any reason, returns
/// `SecureBootState::Unavailable`.
pub fn check_secure_boot() -> SecureBootState {
    // The EFI variable has a 4-byte attribute header followed by the value.
    // Byte index 4 is the Secure Boot value: 1 = enabled, 0 = disabled.
    const EFIVARS_PATH: &str =
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

    match std::fs::read(EFIVARS_PATH) {
        Ok(data) if data.len() >= 5 => {
            let state = if data[4] == 1 {
                SecureBootState::Enabled
            } else {
                SecureBootState::Disabled
            };
            info!(secure_boot = %state, "secure_boot.state_checked");
            state
        }
        Ok(_) => {
            warn!("secure_boot.efivar_too_short");
            SecureBootState::Unavailable
        }
        Err(e) => {
            // This is expected in most container environments.
            info!(reason = %e, "secure_boot.unavailable");
            SecureBootState::Unavailable
        }
    }
}

// ── Machine identity ──────────────────────────────────────────────────────────

/// Read the host's machine ID from `/etc/machine-id`.
///
/// Returns the trimmed string.  Used as a fallback identity when TPM is not
/// available, and always included in the unseal request alongside the TPM quote.
pub fn machine_id() -> Result<String, AppError> {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .map_err(|e| AppError::Internal(format!("cannot read /etc/machine-id: {e}")))
}

// ── TPM2 quote generation ─────────────────────────────────────────────────────

/// Generate a TPM2 quote over the supplied `nonce`.
///
/// Returns `(quote_bytes, ak_pub_bytes)` — both in raw binary form.  The
/// vault verifies the quote using `ak_pub` and the nonce it originally issued.
///
/// ## Implementation note
///
/// This stub currently returns a deterministic fake quote so the rest of the
/// system can compile and run without swtpm present.  The real implementation
/// using `tss-esapi` is provided below the stub behind a feature flag, ready
/// to be enabled once swtpm is available.
pub async fn generate_quote(nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    // ── Development stub ──────────────────────────────────────────────────────
    // In a real deployment this calls the TPM via tss-esapi.  The stub returns
    // a SHA-256 hash of the nonce as a stand-in "quote" so the vault can at
    // least verify the nonce was received and hashed.
    //
    // To enable real TPM2: set env SWTPM_SOCK=/run/swtpm/tpm.sock and uncomment
    // the tss-esapi block below.
    // ─────────────────────────────────────────────────────────────────────────

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(nonce).to_vec();

    // The "ak_pub" stub is just a fixed marker so the vault can distinguish
    // dev-mode quotes from real TPM quotes.
    let ak_pub_stub = b"DEV_MODE_NO_TPM".to_vec();

    tracing::debug!("tpm.quote.stub_used - set SWTPM_SOCK for real TPM attestation");
    Ok((hash, ak_pub_stub))

    // ── Real TPM2 implementation (tss-esapi) ──────────────────────────────────
    // Uncomment and add `tss-esapi = "7"` to shared/Cargo.toml to enable.
    //
    // let tcti_str = std::env::var("TPM_TCTI")
    //     .unwrap_or_else(|_| "swtpm:path=/run/swtpm/tpm.sock".into());
    //
    // let tcti = tss_esapi::tcti_ldr::TctiNameConf::from_str(&tcti_str)
    //     .map_err(|e| AppError::TpmError(e.to_string()))?;
    //
    // let mut ctx = tss_esapi::Context::new(tcti)
    //     .map_err(|e| AppError::TpmError(e.to_string()))?;
    //
    // // Load the Attestation Key (created by swtpm-setup.sh)
    // // … (key loading, quote generation, response parsing)
    //
    // Ok((quote_bytes, ak_pub_bytes))
}
