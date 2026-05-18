//! Vault HTTP route handlers.
//!
//! Routes:
//! - `GET  /vault/nonce`   — issue a fresh nonce for TPM quote binding
//! - `POST /vault/unseal`  — verify attestation, issue initial certificate
//! - `POST /vault/renew`   — issue a renewed certificate (service re-attests)
//! - `POST /vault/revoke`  — add a cert serial to the revocation list
//! - `GET  /vault/crl`     — return current revocation list
//! - `GET  /vault/health`  — liveness probe

use axum::{extract::State, Json};
use tracing::{error, info, instrument, warn};

use shared::{
    errors::AppError,
    models::{IssuanceLogEntry, UnsealRequest, UnsealResponse},
};

use crate::state::AppState;

// ── GET /vault/nonce ──────────────────────────────────────────────────────────

/// Issue a fresh nonce that the client must include in its TPM quote.
///
/// The nonce is registered in the `NonceStore` with a 30-second expiry.
/// Clients should call this immediately before generating their TPM quote.
pub async fn nonce(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let nonce = state.fresh_nonce().await;
    let hex   = hex::encode(&nonce);
    info!(nonce = %hex, "vault.nonce_issued");
    Json(serde_json::json!({ "nonce": hex }))
}

// ── POST /vault/unseal ────────────────────────────────────────────────────────

/// Verify hardware attestation and issue an initial certificate.
///
/// This endpoint does NOT require a client TLS certificate — the calling
/// service doesn't have one yet.  Identity is proven via TPM quote instead.
#[instrument(skip(state, req), fields(
    service    = %req.service_name,
    machine_id = %req.machine_id,
))]
pub async fn unseal(
    State(state): State<AppState>,
    Json(req):    Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, AppError> {
    info!("vault.unseal.received");

    // ── Verify attestation ────────────────────────────────────────────────────
    if let Err(e) = crate::attestation_verifier::verify(
        &req,
        &state.allowlist,
        &state.nonce_store,
    ).await {
        warn!(reason = %e, "vault.unseal.rejected");
        state.log.record_rejection(
            &req.service_name,
            &req.machine_id,
            &e.to_string(),
        ).await;
        return Err(AppError::VaultRejected(e.to_string()));
    }

    // ── Issue certificate ─────────────────────────────────────────────────────
    let bundle = state.issuer
        .issue(&req.service_name)
        .map_err(|e| {
            error!(error = %e, "vault.unseal.issue_failed");
            AppError::Internal(e.to_string())
        })?;

    // ── Log the grant ─────────────────────────────────────────────────────────
    state.log.record_grant(
        &req.service_name,
        &req.machine_id,
        &bundle.serial,
        bundle.expires_at,
    ).await;

    info!(
        serial     = %bundle.serial,
        expires_at = %bundle.expires_at,
        "vault.unseal.granted"
    );

    Ok(Json(UnsealResponse { bundle }))
}

// ── POST /vault/renew ─────────────────────────────────────────────────────────

/// Issue a renewed certificate for a service that is re-attesting.
///
/// For simplicity in Phase 2, renew uses the same attestation flow as unseal.
/// In Phase 3 (mTLS), the client cert CN will be extracted directly from the
/// TLS handshake and used as the service name without re-attestation.
#[instrument(skip(state, req), fields(
    service    = %req.service_name,
    machine_id = %req.machine_id,
))]
pub async fn renew(
    State(state): State<AppState>,
    Json(req):    Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, AppError> {
    info!("vault.renew.received");

    // Re-attest on renewal — same verification as unseal.
    if let Err(e) = crate::attestation_verifier::verify(
        &req,
        &state.allowlist,
        &state.nonce_store,
    ).await {
        warn!(reason = %e, "vault.renew.rejected");
        return Err(AppError::VaultRejected(e.to_string()));
    }

    let bundle = state.issuer
        .issue(&req.service_name)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state.log.record_grant(
        &req.service_name,
        &req.machine_id,
        &bundle.serial,
        bundle.expires_at,
    ).await;

    info!(serial = %bundle.serial, "vault.renew.granted");

    Ok(Json(UnsealResponse { bundle }))
}

// ── POST /vault/revoke ────────────────────────────────────────────────────────

/// Add a certificate serial to the revocation list.
///
/// All services poll `GET /vault/crl` every 30 seconds and reject connections
/// from any peer whose cert serial is on the list.
pub async fn revoke(
    State(state): State<AppState>,
    Json(body):   Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let serial = body
        .get("serial")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("missing serial field".into()))?
        .to_string();

    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given")
        .to_string();

    state.revoke_cert(serial.clone(), reason.clone()).await;

    info!(serial = %serial, reason = %reason, "vault.revoked");

    Ok(Json(serde_json::json!({
        "revoked": serial,
        "reason":  reason,
    })))
}

// ── GET /vault/crl ────────────────────────────────────────────────────────────

/// Return the current certificate revocation list.
///
/// Services poll this every 30 seconds and cache the result.
pub async fn crl(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let list = state.revocation_list().await;
    Json(serde_json::json!({ "revoked_serials": list }))
}

// ── GET /vault/health ─────────────────────────────────────────────────────────

pub async fn health(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status":  "ok",
        "service": "vault-service",
        "issued":  state.issued_count(),
    }))
}
