//! Unified error type for all SecureNet services.
//!
//! `AppError` implements axum's `IntoResponse` so handlers can use `?` and
//! always return a well-formed JSON error body.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Every error that can occur in a SecureNet service.
///
/// Variants are grouped by origin:
/// - `Auth*`  — JWT / authentication failures → 401
/// - `Tls*`   — cert / TLS configuration failures → 500 or 503
/// - `Vault*` — vault communication failures → 503
/// - `NotFound` → 404
/// - `Internal` — catch-all → 500
#[derive(Debug, Error)]
pub enum AppError {
    // ── Auth ──────────────────────────────────────────────────────────────────
    #[error("missing or malformed Authorization header")]
    AuthMissingToken,

    #[error("JWT validation failed: {0}")]
    AuthInvalidToken(String),

    #[error("invalid credentials")]
    AuthBadCredentials,

    // ── TLS / PKI ─────────────────────────────────────────────────────────────
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("certificate parse error: {0}")]
    CertParse(String),

    // ── Vault ─────────────────────────────────────────────────────────────────
    #[error("vault unreachable: {0}")]
    VaultUnreachable(String),

    #[error("vault rejected unseal request: {0}")]
    VaultRejected(String),

    #[error("service is still sealed — vault unseal has not completed")]
    ServiceSealed,

    // ── TPM ───────────────────────────────────────────────────────────────────
    #[error("TPM operation failed: {0}")]
    TpmError(String),

    // ── Business logic ────────────────────────────────────────────────────────
    #[error("{0} not found")]
    NotFound(String),

    // ── Upstream services ─────────────────────────────────────────────────────
    #[error("upstream service error: {0}")]
    Upstream(String),

    // ── Catch-all ─────────────────────────────────────────────────────────────
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::AuthMissingToken      => StatusCode::UNAUTHORIZED,
            AppError::AuthInvalidToken(_)   => StatusCode::UNAUTHORIZED,
            AppError::AuthBadCredentials    => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_)           => StatusCode::NOT_FOUND,
            AppError::ServiceSealed         => StatusCode::SERVICE_UNAVAILABLE,
            AppError::VaultUnreachable(_)   => StatusCode::SERVICE_UNAVAILABLE,
            AppError::VaultRejected(_)      => StatusCode::FORBIDDEN,
            _                               => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Short machine-readable error code included in the JSON body.
    fn code(&self) -> &'static str {
        match self {
            AppError::AuthMissingToken      => "AUTH_MISSING_TOKEN",
            AppError::AuthInvalidToken(_)   => "AUTH_INVALID_TOKEN",
            AppError::AuthBadCredentials    => "AUTH_BAD_CREDENTIALS",
            AppError::TlsConfig(_)          => "TLS_CONFIG_ERROR",
            AppError::CertParse(_)          => "CERT_PARSE_ERROR",
            AppError::VaultUnreachable(_)   => "VAULT_UNREACHABLE",
            AppError::VaultRejected(_)      => "VAULT_REJECTED",
            AppError::ServiceSealed         => "SERVICE_SEALED",
            AppError::TpmError(_)           => "TPM_ERROR",
            AppError::NotFound(_)           => "NOT_FOUND",
            AppError::Upstream(_)           => "UPSTREAM_ERROR",
            AppError::Internal(_)           => "INTERNAL_ERROR",
        }
    }
}

/// Axum integration — every `AppError` becomes a JSON HTTP response.
///
/// Response body shape:
/// ```json
/// { "error": "AUTH_INVALID_TOKEN", "message": "JWT validation failed: …" }
/// ```
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status  = self.status_code();
        let body    = json!({
            "error":   self.code(),
            "message": self.to_string(),
        });
        (status, Json(body)).into_response()
    }
}

// ── Conversions from third-party error types ──────────────────────────────────

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Upstream(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AppError::AuthInvalidToken(e.to_string())
    }
}
