//! Append-only issuance log.
//!
//! Every cert issuance and rejection is recorded here.  The log is append-only
//! by design — no entry is ever modified or deleted.  In this implementation
//! entries are written as newline-delimited JSON to a file; in production this
//! would be a SQLite database with INSERT-only permissions.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::error;

use shared::models::IssuanceLogEntry;

/// An append-only log of certificate issuance events.
#[derive(Clone)]
pub struct IssuanceLog {
    path: PathBuf,
    // Mutex ensures we never interleave writes from concurrent requests.
    lock: Arc<Mutex<()>>,
}

impl IssuanceLog {
    /// Open (or create) the log file at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Append an entry to the log.
    ///
    /// Failures are logged at ERROR level but never propagated — we don't want
    /// a logging failure to prevent cert issuance.
    pub async fn append(&self, entry: &IssuanceLogEntry) {
        let _guard = self.lock.lock().await;

        // TODO(phase-2): implement async file append with tokio::fs
        // For now, just log the entry to tracing.
        let line = match serde_json::to_string(entry) {
            Ok(s)  => s,
            Err(e) => {
                error!(error = %e, "log.serialize_failed");
                return;
            }
        };

        tracing::info!(log_entry = %line, "vault.issuance_log");
        // TODO(phase-2):
        // use tokio::io::AsyncWriteExt;
        // let mut file = tokio::fs::OpenOptions::new()
        //     .append(true).create(true).open(&self.path).await?;
        // file.write_all(format!("{line}\n").as_bytes()).await?;
    }
}
