//! Append-only certificate issuance log.
//!
//! Every issuance and rejection is recorded here as newline-delimited JSON.
//! The log is append-only by design — no record is ever modified or deleted.
//!
//! In development the log is written to a file at `LOG_PATH` (default:
//! `/var/log/vault/issuance.log`).  A `Mutex` serialises concurrent writes so
//! entries are never interleaved.
//!
//! Failures are logged at ERROR level but never propagated — a logging failure
//! must never prevent cert issuance.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{error, info};

use shared::models::IssuanceLogEntry;

// ── IssuanceLog ───────────────────────────────────────────────────────────────

/// An append-only log of certificate issuance events.
#[derive(Clone)]
pub struct IssuanceLog {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl IssuanceLog {
    /// Open (or create) the log at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        info!(path = %path.display(), "issuance_log.opened");
        Self {
            path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Append a granted issuance entry.
    pub async fn record_grant(
        &self,
        service_name: &str,
        machine_id:   &str,
        cert_serial:  &str,
        expires_at:   chrono::DateTime<Utc>,
    ) {
        let entry = IssuanceLogEntry {
            timestamp:    Utc::now(),
            service_name: service_name.to_string(),
            machine_id:   machine_id.to_string(),
            cert_serial:  cert_serial.to_string(),
            expires_at,
            granted:      true,
            reason:       None,
        };
        self.append(&entry).await;
    }

    /// Append a rejected issuance entry.
    pub async fn record_rejection(
        &self,
        service_name: &str,
        machine_id:   &str,
        reason:       &str,
    ) {
        let entry = IssuanceLogEntry {
            timestamp:    Utc::now(),
            service_name: service_name.to_string(),
            machine_id:   machine_id.to_string(),
            cert_serial:  String::new(),
            expires_at:   Utc::now(), // unused for rejections
            granted:      false,
            reason:       Some(reason.to_string()),
        };
        self.append(&entry).await;
    }

    /// Core append — serialises to JSON and writes atomically.
    async fn append(&self, entry: &IssuanceLogEntry) {
        let line = match serde_json::to_string(entry) {
            Ok(s)  => format!("{s}\n"),
            Err(e) => {
                error!(error = %e, "issuance_log.serialize_failed");
                return;
            }
        };

        // Always emit to tracing — visible in Jaeger regardless of file state.
        info!(
            granted      = entry.granted,
            service      = %entry.service_name,
            machine_id   = %entry.machine_id,
            cert_serial  = %entry.cert_serial,
            reason       = ?entry.reason,
            "vault.issuance_log"
        );

        // Write to file — hold the lock only during the write.
        let _guard = self.lock.lock().await;

        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                error!(error = %e, "issuance_log.mkdir_failed");
                return;
            }
        }

        match tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .await
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    error!(error = %e, "issuance_log.write_failed");
                }
            }
            Err(e) => {
                error!(error = %e, path = %self.path.display(), "issuance_log.open_failed");
            }
        }
    }
}
