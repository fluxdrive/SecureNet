//! API Gateway — the only public-facing service.
//!
//! Handles JWT authentication and proxies authenticated requests to the
//! internal services over mTLS.
//!
//! ## Routes
//!
//! | Method | Path            | Auth | Proxies to             |
//! |--------|-----------------|------|------------------------|
//! | POST   | /auth/token     | No   | (handled here)         |
//! | GET    | /users/:id      | JWT  | user-service           |
//! | GET    | /users          | JWT  | user-service           |
//! | GET    | /orders/:id     | JWT  | order-service          |
//! | GET    | /orders         | JWT  | order-service          |
//! | GET    | /health         | No   | (handled here)         |

mod jwt;
mod middleware;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    routing::{get, post},
    Json, Router,
};
use tokio_rustls::TlsAcceptor;
use tracing::info;

use shared::{
    attestation::check_secure_boot,
    errors::AppError,
    models::{LoginRequest, TokenResponse},
};

use jwt::{JwtKeys, UserStore};

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub jwt_keys:      JwtKeys,
    pub user_store:    UserStore,
    pub mtls_client:   reqwest::Client,
    pub user_svc_url:  String,
    pub order_svc_url: String,
    pub cert_serial:   Arc<tokio::sync::RwLock<String>>,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let jaeger = std::env::var("JAEGER_ENDPOINT").ok();
    shared::telemetry::init_telemetry("api-gateway", jaeger.as_deref())?;
    info!("api-gateway starting");

    let sb = check_secure_boot();
    info!(secure_boot = %sb, "boot.secure_boot_checked");

    // Vault unseal + cert rotation
    let vault_url = std::env::var("VAULT_URL")
        .unwrap_or_else(|_| "http://localhost:8003".into());

    let boot = shared::boot::run_gateway("api-gateway", &vault_url).await?;

    // JWT keys
    let jwt_keys = JwtKeys::load_or_generate()?;

    // mTLS client for proxying to backends
    let mtls_client = shared::boot::mtls_client(&boot.bundle)?;

    let state = AppState {
        jwt_keys,
        user_store:    UserStore::seeded(),
        mtls_client,
        user_svc_url:  std::env::var("USER_SERVICE_URL")
                           .unwrap_or_else(|_| "https://localhost:8001".into()),
        order_svc_url: std::env::var("ORDER_SERVICE_URL")
                           .unwrap_or_else(|_| "https://localhost:8002".into()),
        cert_serial:   Arc::new(tokio::sync::RwLock::new(boot.bundle.serial.clone())),
    };

    // ── Router ────────────────────────────────────────────────────────────────
    // Public routes (no JWT required)
    let public = Router::new()
        .route("/auth/token", post(auth_token))
        .route("/health",     get(health));

    // Protected routes — JWT middleware applied
    let protected = Router::new()
        .route("/users/:id", get(proxy_user))
        .route("/users",     get(proxy_users))
        .route("/orders/:id", get(proxy_order))
        .route("/orders",    get(proxy_orders))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::jwt_middleware,
        ));

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state);

    // ── Bind mTLS server ──────────────────────────────────────────────────────
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;

    let tls_config   = boot.tls_config.current().await;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(%addr, serial = %boot.bundle.serial, "api-gateway ready (mTLS)");

    serve_mtls(addr, app, tls_acceptor, boot.tls_config).await?;

    shared::telemetry::shutdown_telemetry();
    Ok(())
}

// ── mTLS accept loop ──────────────────────────────────────────────────────────

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

// ── Auth handler ──────────────────────────────────────────────────────────────

async fn auth_token(
    State(state): State<AppState>,
    Json(req):    Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let roles = state.user_store
        .authenticate(&req.username, &req.password)
        .ok_or(AppError::AuthBadCredentials)?;

    let token = state.jwt_keys.sign(&req.username, roles)?;

    info!(sub = %req.username, "auth.token_issued");

    Ok(Json(TokenResponse {
        access_token: token,
        token_type:   "Bearer".into(),
        expires_in:   3600,
    }))
}

// ── Proxy handlers ────────────────────────────────────────────────────────────

async fn proxy_user(
    Path(id):     Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    proxy_get(&state.mtls_client, &format!("{}/users/{id}", state.user_svc_url)).await
}

async fn proxy_users(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    proxy_get(&state.mtls_client, &format!("{}/users", state.user_svc_url)).await
}

async fn proxy_order(
    Path(id):     Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    proxy_get(&state.mtls_client, &format!("{}/orders/{id}", state.order_svc_url)).await
}

async fn proxy_orders(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    proxy_get(&state.mtls_client, &format!("{}/orders", state.order_svc_url)).await
}

async fn proxy_get(
    client: &reqwest::Client,
    url:    &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, url, "proxy.upstream_error");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "UPSTREAM_ERROR",
                    "message": e.to_string(),
                    "url": url,
                })),
            )
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "PARSE_ERROR",
                "message": e.to_string(),
            })),
        ))?;

    if !status.is_success() {
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(body),
        ));
    }

    Ok(Json(body))
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn health(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let serial = state.cert_serial.read().await.clone();
    Json(serde_json::json!({
        "status":      "ok",
        "service":     "api-gateway",
        "sealed":      false,
        "cert_serial": serial,
    }))
}
