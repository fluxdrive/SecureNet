//! x509 certificate issuance using `rcgen`.
//!
//! `Issuer` holds the root CA key in memory and signs leaf certificates for
//! each service.  Every issued cert has a 5-minute TTL and SANs that cover
//! all the DNS names a service might be reached under.
//!
//! ## Certificate hierarchy
//!
//! ```text
//! Root CA  (long-lived, baked into vault image)
//! └── <service-name>  (5-minute TTL, issued at boot and on renewal)
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use chrono::Utc;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;
use tracing::info;

use shared::models::CertBundle;

/// TTL for issued leaf certificates in seconds (5 minutes).
const CERT_TTL_SECS: i64 = 300;

/// Monotonically increasing serial counter for issued certs.
static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

// ── Issuer ────────────────────────────────────────────────────────────────────

/// Holds the root CA in memory and signs leaf certificates on demand.
pub struct Issuer {
    ca_cert_pem: String,
    ca_key_pair: KeyPair,
}

impl Issuer {
    /// Load the root CA from PEM strings.
    ///
    /// Both strings come from the Kubernetes Secret mounted at startup.
    pub fn from_pem(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self> {
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)
            .context("failed to parse CA private key")?;

        info!("issuer.ca_loaded");

        Ok(Self {
            ca_cert_pem: ca_cert_pem.to_string(),
            ca_key_pair,
        })
    }

    /// Issue a new `CertBundle` for the named service.
    ///
    /// SANs include:
    /// - `<service_name>`
    /// - `<service_name>.securenet.svc.cluster.local`
    /// - `localhost` / `127.0.0.1`
    ///
    /// Extended key usage includes both ServerAuth and ClientAuth — required
    /// for mutual TLS where the same cert is presented as both.
    pub fn issue(&self, service_name: &str) -> Result<CertBundle> {
        let serial = SERIAL_COUNTER.fetch_add(1, Ordering::SeqCst);
        let now    = OffsetDateTime::now_utc();
        let expiry = now + time::Duration::seconds(CERT_TTL_SECS);

        // ── Leaf cert params ──────────────────────────────────────────────────
        let mut params = CertificateParams::new(vec![
            service_name.to_string(),
            format!("{service_name}.securenet.svc.cluster.local"),
            "localhost".to_string(),
        ])
        .context("failed to build cert params")?;

        params.distinguished_name.push(
            DnType::CommonName,
            format!("{service_name}.securenet"),
        );
        params.distinguished_name.push(
            DnType::OrganizationName,
            "SecureNet",
        );

        // IP SAN for direct 127.0.0.1 connections
        params.subject_alt_names.push(SanType::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ));

        params.not_before = now;
        params.not_after  = expiry;
        params.is_ca      = IsCa::NoCa;

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        params.serial_number = Some(rcgen::SerialNumber::from(serial));

        // ── Generate fresh key pair for this leaf cert ────────────────────────
        let leaf_key = KeyPair::generate()
            .context("failed to generate leaf key pair")?;

        // ── Reconstruct CA cert for signing ──────────────────────────────────
        let ca_params = CertificateParams::from_ca_cert_pem(&self.ca_cert_pem)
            .context("failed to parse CA cert PEM")?;

        let ca_cert = ca_params
            .self_signed(&self.ca_key_pair)
            .context("failed to reconstruct CA cert")?;

        // ── Sign leaf with CA ─────────────────────────────────────────────────
        let leaf_cert = params
            .signed_by(&leaf_key, &ca_cert, &self.ca_key_pair)
            .context("CA signing failed")?;

        let serial_hex = format!("{serial:016x}");
        let expires_at = Utc::now() + chrono::Duration::seconds(CERT_TTL_SECS);

        info!(
            service    = service_name,
            serial     = %serial_hex,
            expires_at = %expires_at,
            "issuer.cert_issued"
        );

        Ok(CertBundle {
            cert_pem:   leaf_cert.pem(),
            key_pem:    leaf_key.serialize_pem(),
            ca_pem:     self.ca_cert_pem.clone(),
            expires_at,
            serial:     serial_hex,
        })
    }

    /// The CA certificate PEM — returned to services so they can verify peers.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }
}

// ── Bootstrap CA generation (used by gen-bootstrap-cert.sh only) ─────────────

/// Generate a new self-signed root CA.
///
/// Called once at build time to produce the CA material baked into the vault
/// image.  Never called at runtime.  Returns `(ca_cert_pem, ca_key_pem)`.
pub fn generate_ca() -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec![])
        .context("failed to create CA params")?;

    params.distinguished_name.push(DnType::CommonName, "SecureNet Root CA");
    params.distinguished_name.push(DnType::OrganizationName, "SecureNet");

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after  = now + time::Duration::days(3650); // 10 years
    params.is_ca      = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate()
        .context("failed to generate CA key pair")?;

    let cert = params
        .self_signed(&key_pair)
        .context("failed to self-sign CA")?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}
