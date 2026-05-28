//! Order Service — internal only, mTLS required.
//!
//! Returns order data and resolves the associated user by calling
//! user-service over mTLS.  Both the inbound server and outbound client
//! present and verify certificates.

use std::collections::HashMap;
use std::sync::Arc;
use std::error::Error as StdError;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use tokio_rustls::TlsAcceptor;
use tracing::info;
use uuid::Uuid;

use shared::{
    attestation::check_secure_boot,
    models::{HealthResponse, Order, OrderWithUser, User},
};

// ── In-memory order store ─────────────────────────────────────────────────────

fn seed_orders() -> HashMap<Uuid, Order> {
    let mut m = HashMap::new();
    let orders = vec![
        Order {
            id:      "660e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
            user_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
            item:    "Neuralink N1 Implant".into(),
            qty:     1,
        },
        Order {
            id:      "660e8400-e29b-41d4-a716-446655440002".parse().unwrap(),
            user_id: "550e8400-e29b-41d4-a716-446655440002".parse().unwrap(),
            item:    "Neural Interface Headset".into(),
            qty:     2,
        },
    ];
    for o in orders { m.insert(o.id, o); }
    m
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    orders:       Arc<HashMap<Uuid, Order>>,
    user_svc_url: String,
    /// mTLS client for calling user-service
    mtls_client:  reqwest::Client,
    cert_serial:  Arc<tokio::sync::RwLock<String>>,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("order-service", jaeger.as_deref())?;
    info!("order-service starting");

    let sb = check_secure_boot();
    info!(secure_boot = %sb, "boot.secure_boot_checked");

    let vault_url = std::env::var("VAULT_URL")
        .unwrap_or_else(|_| "http://localhost:8003".into());

    let boot = shared::boot::run("order-service", &vault_url).await?;

    // Build mTLS client for outbound calls to user-service
    let mtls_client = shared::boot::mtls_client(&boot.bundle)?;

    let user_svc_url = std::env::var("USER_SERVICE_URL")
        .unwrap_or_else(|_| "https://localhost:8001".into());

    let state = AppState {
        orders:       Arc::new(seed_orders()),
        user_svc_url,
        mtls_client,
        cert_serial:  Arc::new(tokio::sync::RwLock::new(boot.bundle.serial.clone())),
    };

    let app = Router::new()
        .route("/orders/:id", get(get_order))
        .route("/orders",     get(list_orders))
        .route("/health",     get(health))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8002".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;

    let tls_config   = boot.tls_config.current().await;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(%addr, serial = %boot.bundle.serial, "order-service ready (mTLS)");

    serve_mtls(addr, app, tls_acceptor, boot.tls_config).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}

// ── mTLS accept loop (same pattern as user-service) ───────────────────────────

async fn serve_mtls(
    addr:       std::net::SocketAddr,
    app:        Router,
    _acceptor:  TlsAcceptor,
    tls_config: shared::rotation::RotatingTlsConfig,
) -> Result<()> {
    use std::convert::Infallible;
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tower::Service;

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let current_config      = tls_config.current().await;
        let acceptor            = TlsAcceptor::from(current_config);
        let app_clone           = app.clone();

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

async fn get_order(
    Path(id):     Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<OrderWithUser>, StatusCode> {
    let order = state.orders
        .get(&id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Call user-service over mTLS to resolve the user
    let user_url = format!("{}/users/{}", state.user_svc_url, order.user_id);

    let response = state.mtls_client
        .get(&user_url)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                error  = %e,
                source = ?e.source().map(|s| s.to_string()),
                url    = %user_url,
                "user_service.call_failed"
            );
            StatusCode::BAD_GATEWAY
        })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            url    = %user_url,
            "user_service.bad_status"
        );
        return Err(StatusCode::BAD_GATEWAY);
    }

    let user: User = response
        .json()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "user_service.parse_failed");
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(OrderWithUser { order, user }))
}

async fn list_orders(
    State(state): State<AppState>,
) -> Json<Vec<Order>> {
    Json(state.orders.values().cloned().collect())
}

async fn health(
    State(state): State<AppState>,
) -> Json<HealthResponse> {
    let serial = state.cert_serial.read().await.clone();
    Json(HealthResponse {
        status:      "ok",
        service:     "order-service".into(),
        version:     env!("CARGO_PKG_VERSION"),
        sealed:      false,
        cert_serial: Some(serial),
    })
}
