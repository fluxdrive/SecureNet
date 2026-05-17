//! Vault HTTP route handlers.
//!
//! Routes:
//! - `POST /vault/unseal` — verify TPM quote, issue initial cert
//! - `POST /vault/renew`  — verify mTLS identity, issue renewed cert
//! - `GET  /vault/health` — liveness probe

use axum::{extract::State, Json};
use tracing::{error, info, instrument};

use shared::{
    errors::AppError,
    models::{UnsealRequest, UnsealResponse},
};

// TODO(phase-2): define AppState with Issuer + IssuanceLog + Allowlist

/// `POST /vault/unseal`
///
/// The first call a service makes.  No client cert is required here — the
/// service doesn't have one yet.  Identity is proved via TPM quote instead.
#[instrument(skip(req))]
pub async fn unseal(
    // State(state): State<AppState>,
    Json(req): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, AppError> {
    info!(service = %req.service_name, machine_id = %req.machine_id, "vault.unseal.received");

    // TODO(phase-2):
    // 1. attestation_verifier::verify(&req, &state.allowlist)?
    // 2. let bundle = state.issuer.issue(&req.service_name)?
    // 3. state.log.append(&IssuanceLogEntry { granted: true, ... }).await
    // 4. return Ok(Json(UnsealResponse { bundle }))

    Err(AppError::Internal("unseal not yet implemented — phase 2".into()))
}

/// `POST /vault/renew`
///
/// Called by the rotation background task.  The service presents its current
/// (still-valid) mTLS cert as authentication; the vault issues a fresh one.
#[instrument]
pub async fn renew(
    // State(state): State<AppState>,
    // TODO(phase-2): extract service name from mTLS client cert CN
) -> Result<Json<UnsealResponse>, AppError> {
    // TODO(phase-2): verify client cert, issue new bundle, log entry
    Err(AppError::Internal("renew not yet implemented — phase 2".into()))
}
