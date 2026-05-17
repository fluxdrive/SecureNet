//! x509 certificate issuance using `rcgen`.
//!
//! `Issuer` holds the root CA key in memory and signs certificate requests
//! from services.  Each issued cert has a 5-minute TTL and SANs covering the
//! service's DNS names and localhost.

use anyhow::Result;

use shared::models::CertBundle;

/// The certificate issuer — holds the root CA in memory.
pub struct Issuer {
    // TODO(phase-2): ca_cert: rcgen::Certificate,
    // TODO(phase-2): ca_key:  rcgen::KeyPair,
}

impl Issuer {
    /// Load the root CA from PEM strings.
    ///
    /// In production these come from a Kubernetes Secret mounted at startup.
    pub fn from_pem(_ca_cert_pem: &str, _ca_key_pem: &str) -> Result<Self> {
        // TODO(phase-2): parse CA cert + key with rcgen
        Ok(Self {})
    }

    /// Issue a new `CertBundle` for the named service.
    ///
    /// The certificate will have:
    /// - Subject CN: `<service_name>.securenet`
    /// - SANs: `<service_name>`, `<service_name>.securenet.svc.cluster.local`,
    ///         `localhost`, `127.0.0.1`
    /// - TTL: 300 seconds
    pub fn issue(&self, service_name: &str) -> Result<CertBundle> {
        // TODO(phase-2): implement with rcgen
        let _ = service_name;
        anyhow::bail!("issuer not yet implemented — phase 2")
    }
}
