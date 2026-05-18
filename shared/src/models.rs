//! Wire types shared across all services.
//!
//! All types derive `Serialize`/`Deserialize` so they can travel over HTTP as
//! JSON.  Types that cross service boundaries also derive `Clone` so they can
//! be stored in shared state behind an `Arc`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Domain types ──────────────────────────────────────────────────────────────

/// A registered user in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id:    Uuid,
    pub name:  String,
    pub email: String,
}

/// An order placed by a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id:      Uuid,
    pub user_id: Uuid,
    pub item:    String,
    pub qty:     u32,
}

/// An order with its user data resolved (returned by order-service).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderWithUser {
    pub order: Order,
    pub user:  User,
}

// ── TLS / PKI types ───────────────────────────────────────────────────────────

/// A short-lived TLS certificate bundle issued by the vault service.
///
/// All three PEM strings are required.  `expires_at` is informational — the
/// rotation task uses it to schedule the next renewal at 90 % of the TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBundle {
    /// PEM-encoded leaf certificate (the service's identity).
    pub cert_pem:   String,
    /// PEM-encoded private key for the leaf certificate.
    pub key_pem:    String,
    /// PEM-encoded root CA certificate used to verify peers.
    pub ca_pem:     String,
    /// UTC timestamp when the leaf certificate expires.
    pub expires_at: DateTime<Utc>,
    /// x509 serial number as a hex string — used in trace events.
    pub serial:     String,
}

impl CertBundle {
    /// Returns how many seconds remain until expiry, or 0 if already expired.
    pub fn ttl_secs(&self) -> u64 {
        let now  = Utc::now();
        let diff = self.expires_at.signed_duration_since(now);
        diff.num_seconds().max(0) as u64
    }

    /// Returns the instant at which the rotation task should trigger renewal.
    ///
    /// We renew at 90 % of TTL to guarantee there is always time to retry on
    /// failure before the cert actually expires.
    pub fn renew_at(&self) -> DateTime<Utc> {
        let ttl    = self.expires_at.signed_duration_since(Utc::now());
        let offset = chrono::Duration::seconds((ttl.num_seconds() as f64 * 0.9) as i64);
        Utc::now() + offset
    }
}

// ── JWT types ─────────────────────────────────────────────────────────────────

/// JWT claims embedded in every access token issued by the gateway.
///
/// `sub` holds the username; `roles` is a list of string role names.
/// `exp` and `iat` are standard Unix timestamps (seconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the authenticated username.
    pub sub:     String,
    /// Issued-at (Unix seconds).
    pub iat:     i64,
    /// Expiry (Unix seconds).
    pub exp:     i64,
    /// Issuer — should be "securenet-gateway".
    pub iss:     String,
    /// Roles granted to this user.
    pub roles:   Vec<String>,
}

/// Credentials submitted to `POST /auth/token`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Successful response from `POST /auth/token`.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type:   String,
    pub expires_in:   i64,
}

// ── Vault / attestation types ─────────────────────────────────────────────────

/// Request body for `POST /vault/unseal`.
///
/// The service presents its hardware identity.  In production this is a signed
/// TPM2 quote; in `dev` mode (when swtpm is unavailable) it falls back to a
/// plain machine-id string logged as a warning.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealRequest {
    /// Unique name of the requesting service (e.g. `"user-service"`).
    pub service_name: String,
    /// `/etc/machine-id` or equivalent deterministic host identifier.
    pub machine_id:   String,
    /// Hex-encoded TPM2 quote.  Empty string in dev/fallback mode.
    pub tpm_quote:    String,
    /// Hex-encoded nonce from `GET /vault/nonce`.
    pub nonce:        String,
    /// Hex-encoded TPM2 AK public area.  Empty string in dev mode.
    pub ak_pub:       String,
}

/// Successful response from `POST /vault/unseal` or `POST /vault/renew`.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub bundle: CertBundle,
}

/// A single entry in the vault's append-only issuance log.
#[derive(Debug, Serialize, Deserialize)]
pub struct IssuanceLogEntry {
    pub timestamp:    DateTime<Utc>,
    pub service_name: String,
    pub machine_id:   String,
    pub cert_serial:  String,
    pub expires_at:   DateTime<Utc>,
    pub granted:      bool,
    /// Human-readable rejection reason; `None` when `granted == true`.
    pub reason:       Option<String>,
}

// ── Health check ──────────────────────────────────────────────────────────────

/// Standard health response returned by every service's `GET /health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status:      &'static str,
    pub service:     String,
    pub version:     &'static str,
    /// Whether this service has successfully unsealed.
    pub sealed:      bool,
    /// Serial of the currently-active TLS certificate.
    pub cert_serial: Option<String>,
}
