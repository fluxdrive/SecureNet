//! Shared application state for the vault service.
//!
//! `AppState` is cloned cheaply into every request handler via axum's
//! `State` extractor.  All mutable fields are behind `Arc<Mutex/RwLock>`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::attestation_verifier::{Allowlist, NonceStore};
use crate::issuer::Issuer;
use crate::log::IssuanceLog;

/// Vault application state — cheap to clone, all interior mutability.
#[derive(Clone)]
pub struct AppState {
    pub issuer:      Arc<Issuer>,
    pub log:         IssuanceLog,
    pub allowlist:   Allowlist,
    pub nonce_store: NonceStore,

    /// Revoked cert serials → reason.
    revoked:         Arc<RwLock<HashMap<String, String>>>,
    /// Total certs issued since startup (for health endpoint).
    issued:          Arc<AtomicU64>,
}

impl AppState {
    pub fn new(
        issuer:    Issuer,
        log:       IssuanceLog,
        allowlist: Allowlist,
    ) -> Self {
        Self {
            issuer:      Arc::new(issuer),
            log,
            allowlist,
            nonce_store: NonceStore::new(),
            revoked:     Arc::new(RwLock::new(HashMap::new())),
            issued:      Arc::new(AtomicU64::new(0)),
        }
    }

    /// Generate and register a fresh nonce, returning its raw bytes.
    pub async fn fresh_nonce(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.nonce_store.register(nonce.clone()).await;
        nonce
    }

    /// Add a serial to the revocation list.
    pub async fn revoke_cert(&self, serial: String, reason: String) {
        self.revoked.write().await.insert(serial, reason);
    }

    /// Return a list of all revoked serials.
    pub async fn revocation_list(&self) -> Vec<String> {
        self.revoked.read().await.keys().cloned().collect()
    }

    /// Check if a serial is revoked.
    pub async fn is_revoked(&self, serial: &str) -> bool {
        self.revoked.read().await.contains_key(serial)
    }

    /// Increment and return the issued cert counter.
    pub fn increment_issued(&self) -> u64 {
        self.issued.fetch_add(1, Ordering::Relaxed)
    }

    /// Current issued cert count.
    pub fn issued_count(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }
}
