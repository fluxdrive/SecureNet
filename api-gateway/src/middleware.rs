//! Axum middleware — JWT validation and trace context propagation.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::{info, instrument, warn};

use shared::{errors::AppError, models::Claims};

use crate::AppState;

// ── JWT middleware ────────────────────────────────────────────────────────────

/// Extract and validate a Bearer JWT from the Authorization header.
///
/// On success, injects `X-User-Id` and `X-User-Roles` headers so downstream
/// services can read the authenticated identity without re-validating the JWT.
pub async fn jwt_middleware(
    State(state): State<AppState>,
    mut req:      Request<Body>,
    next:         Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::AuthMissingToken)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AppError::AuthMissingToken)?;

    let claims = state.jwt_keys.validate(token)?;

    info!(sub = %claims.sub, "jwt.validated");

    // Inject identity headers for downstream services
    let headers = req.headers_mut();
    headers.insert(
        "x-user-id",
        claims.sub.parse().map_err(|_| AppError::Internal("bad sub".into()))?,
    );
    headers.insert(
        "x-user-roles",
        claims.roles.join(",").parse()
            .map_err(|_| AppError::Internal("bad roles".into()))?,
    );

    Ok(next.run(req).await)
}

// ── Trace context middleware ──────────────────────────────────────────────────

/// Extract W3C traceparent from inbound requests and set as parent span.
pub async fn trace_middleware(
    req:  Request<Body>,
    next: Next,
) -> Response {
    let cx = shared::telemetry::extract_context(req.headers());
    tracing_opentelemetry::OpenTelemetrySpanExt::set_parent(
        &tracing::Span::current(),
        cx,
    );
    next.run(req).await
}
