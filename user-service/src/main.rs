//! User Service — internal only, mTLS required.
//!
//! Serves user data to the API gateway and order-service.
//! Rejects any connection that does not present a valid client certificate.
//!
//! ## Boot sequence
//! 1. Telemetry
//! 2. Secure Boot check
//! 3. Vault unseal → cert bundle
//! 4. Spawn cert rotation task
//! 5. Bind mTLS server on :8001

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::info;
use uuid::Uuid;

use shared::{
    attestation::check_secure_boot,
    models::{HealthResponse, User},
};

// ── In-memory user store ──────────────────────────────────────────────────────

fn seed_users() -> HashMap<Uuid, User> {
    let mut m = HashMap::new();
    let users = vec![
        User {
            id:    "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
            name:  "Alice Chen".into(),
            email: "alice@securenet.dev".into(),
        },
        User {
            id:    "550e8400-e29b-41d4-a716-446655440002".parse().unwrap(),
            name:  "Bob Santos".into(),
            email: "bob@securenet.dev".into(),
        },
        User {
            id:    "550e8400-e29b-41d4-a716-446655440003".parse().unwrap(),
            name:  "Carol White".into(),
            email: "carol@securenet.dev".into(),
        },
    ];
    for u in users { m.insert(u.id, u); }
    m
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    users:       Arc<HashMap<Uuid, User>>,
    cert_serial: Arc<tokio::sync::RwLock<String>>,
    sealed:      Arc<std::sync::atomic::AtomicBool>,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Telemetry
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("user-service", jaeger.as_deref())?;
    info!("user-service starting");

    // 2. Secure Boot check
    let sb = check_secure_boot();
    info!(secure_boot = %sb, "boot.secure_boot_checked");

    // 3. Vault unseal + rotation
    let vault_url = std::env::var("VAULT_URL")
        .unwrap_or_else(|_| "http://localhost:8003".into());

    let boot = shared::boot::run("user-service", &vault_url).await?;

    let state = AppState {
        users:       Arc::new(seed_users()),
        cert_serial: Arc::new(tokio::sync::RwLock::new(boot.bundle.serial.clone())),
        sealed:      Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    // 4. Router
    let app = Router::new()
        .route("/users/:id", get(get_user))
        .route("/users",     get(list_users))
        .route("/health",    get(health))
        .with_state(state);

    // 5. Bind — plain TCP for Phase 3, mTLS acceptor wraps it
    let port = std::env::var("PORT").unwrap_or_else(|_| "8001".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;

    // Build rustls acceptor from rotating config
    let tls_config   = boot.tls_config.current().await;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(%addr, serial = %boot.bundle.serial, "user-service ready (mTLS)");

    // Serve with manual TLS accept loop so we can swap certs
    serve_mtls(addr, app, tls_acceptor, boot.tls_config).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}

// ── mTLS accept loop ──────────────────────────────────────────────────────────

/// Accept TCP connections and upgrade them to TLS using the rotating config.
///
/// The key behaviour: each new connection reads the *current* ServerConfig
/// from the RwLock, so cert rotations are picked up immediately.
async fn serve_mtls(
    addr:       std::net::SocketAddr,
    app:        Router,
    _acceptor:  TlsAcceptor,
    tls_config: shared::rotation::RotatingTlsConfig,
) -> Result<()> {
    use std::convert::Infallible;
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tower::Service;

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;

        // Read the CURRENT config at accept time — picks up rotations.
        let current_config = tls_config.current().await;
        let acceptor        = TlsAcceptor::from(current_config);
        let app_clone       = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io      = TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let mut app = app_clone.clone();
                        async move {
                            Ok::<_, Infallible>(app.call(req).await.unwrap_or_else(|_| {
                                axum::response::Response::builder()
                                    .status(500)
                                    .body(axum::body::Body::empty())
                                    .unwrap()
                            }))
                        }
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(error = %e, peer = %peer_addr, "connection closed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, peer = %peer_addr, "tls.handshake_failed");
                }
            }
        });
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn get_user(
    Path(id):     Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state.users
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn list_users(
    State(state): State<AppState>,
) -> Json<Vec<User>> {
    Json(state.users.values().cloned().collect())
}

async fn health(
    State(state): State<AppState>,
) -> Json<HealthResponse> {
    let serial = state.cert_serial.read().await.clone();
    Json(HealthResponse {
        status:      "ok",
        service:     "user-service".into(),
        version:     env!("CARGO_PKG_VERSION"),
        sealed:      state.sealed.load(std::sync::atomic::Ordering::Relaxed),
        cert_serial: Some(serial),
    })
}
