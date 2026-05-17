//! rustls configuration builders.
//!
//! Every service calls `server_config` and `client_config` with its
//! `CertBundle`.  Both enforce mutual TLS — the server requires a client
//! certificate, and the client always presents one.

use std::sync::Arc;

use rustls::{
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};

use crate::{errors::AppError, models::CertBundle};

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a rustls `ServerConfig` from a `CertBundle`.
///
/// The server will:
/// - present `bundle.cert_pem` as its identity
/// - require clients to present a certificate signed by `bundle.ca_pem`
/// - reject connections without a valid client certificate (mTLS enforced)
pub fn server_config(bundle: &CertBundle) -> Result<ServerConfig, AppError> {
    let cert_chain = parse_cert_chain(&bundle.cert_pem)?;
    let private_key = parse_private_key(&bundle.key_pem)?;
    let root_store  = build_root_store(&bundle.ca_pem)?;

    // Require and verify client certs — this is what makes it *mutual* TLS.
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AppError::TlsConfig(e.to_string()))?;

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| AppError::TlsConfig(e.to_string()))
}

/// Build a rustls `ClientConfig` from a `CertBundle`.
///
/// The client will:
/// - present `bundle.cert_pem` as its identity on every outbound connection
/// - only trust servers whose cert chains up to `bundle.ca_pem`
pub fn client_config(bundle: &CertBundle) -> Result<ClientConfig, AppError> {
    let cert_chain  = parse_cert_chain(&bundle.cert_pem)?;
    let private_key = parse_private_key(&bundle.key_pem)?;
    let root_store  = build_root_store(&bundle.ca_pem)?;

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(|e| AppError::TlsConfig(e.to_string()))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a PEM certificate chain into a `Vec<rustls::pki_types::CertificateDer>`.
pub fn parse_cert_chain(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, AppError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    certs(&mut reader)
        .map(|r| r.map_err(|e| AppError::CertParse(e.to_string())))
        .collect()
}

/// Parse the first PKCS#8 private key found in a PEM block.
pub fn parse_private_key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, AppError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    // Bind to a local variable before the reader is dropped — fixes the
    // temporary lifetime issue with the iterator returned by pkcs8_private_keys.
    let key = pkcs8_private_keys(&mut reader)
        .next()
        .ok_or_else(|| AppError::CertParse("no private key found in PEM".into()))?
        .map(rustls::pki_types::PrivateKeyDer::Pkcs8)
        .map_err(|e| AppError::CertParse(e.to_string()));
    key
}

/// Build a `RootCertStore` from a PEM-encoded CA certificate.
pub fn build_root_store(ca_pem: &str) -> Result<RootCertStore, AppError> {
    let mut store  = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(ca_pem.as_bytes());
    let certs: Vec<_> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::CertParse(e.to_string()))?;

    for cert in certs {
        store
            .add(cert)
            .map_err(|e| AppError::CertParse(e.to_string()))?;
    }

    Ok(store)
}
