//! HTTP surface (PLAN.md §8, ADR-0005 §1): axum router over the store.
//!
//! Handlers are thin: wire-shape validation lives in citadel-proto types,
//! semantics in [`crate::store`]. Errors map to the stable wire taxonomy
//! (citadel_proto::error); auth failures always collapse to `unauthorized`
//! (ADR-0003 §1). Fanout is a broadcast channel: submit publishes to it
//! AFTER commit and only on Created — a Replayed submit already fanned out
//! on its original POST, and SendError here just means zero live
//! subscribers (GET ?after= sync is the catch-up path).

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use citadel_proto::delivery::{MessagesPage, SubmitMessageRequest, SubmitMessageResponse};
use citadel_proto::envelope::Envelope;
use citadel_proto::error::{ErrorCode, ErrorResponse};
use citadel_proto::ids::{DeviceId, GroupId};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::trace::TraceLayer;

use crate::auth::{self, AuthError};
use crate::gateway;
use crate::store::{self, StoreError, SubmitOutcome};

/// Live-fanout channel capacity. A lagging subscriber misses frames and
/// catches up via GET ?after= sync (ADR-0005 §1: the gateway is a hint, the
/// sync cursor is authoritative).
pub const FANOUT_CAPACITY: usize = 1024;

/// One fanned-out message: its group and the fully populated envelope.
pub type FanoutEvent = (GroupId, Arc<Envelope>);

/// Shared service state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub fanout: broadcast::Sender<FanoutEvent>,
}

impl AppState {
    pub fn new(pool: PgPool) -> Self {
        let (fanout, _) = broadcast::channel(FANOUT_CAPACITY);
        Self { pool, fanout }
    }
}

/// The delivery-service router: health probes, the M2 message path
/// (ADR-0005 §1), and the WebSocket gateway (receive/fanout only — sends go
/// over REST so seq assignment and dedup have one home, decision #4).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/groups/{gid}/messages", post(submit_message))
        .route("/v1/groups/{gid}/messages", get(fetch_messages))
        .route("/v1/gateway", get(gateway_upgrade))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn error_response(code: ErrorCode, message: &str) -> ApiError {
    let status =
        StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorResponse::new(code, message)))
}

fn auth_error(err: AuthError) -> ApiError {
    match err {
        AuthError::Unauthorized => error_response(ErrorCode::Unauthorized, "unauthorized"),
        AuthError::Database(e) => {
            tracing::error!(error = %e, "auth store error");
            error_response(ErrorCode::Internal, "internal error")
        }
    }
}

fn store_error(err: StoreError) -> ApiError {
    match err {
        StoreError::InvalidRequest(msg) => error_response(ErrorCode::InvalidRequest, &msg),
        StoreError::Forbidden(msg) => error_response(ErrorCode::Forbidden, &msg),
        StoreError::Unauthorized => error_response(ErrorCode::Unauthorized, "unauthorized"),
        StoreError::UnsupportedVersion { .. } => {
            error_response(ErrorCode::UnsupportedVersion, &err.to_string())
        }
        StoreError::Db(e) => {
            tracing::error!(error = %e, "message store error");
            error_response(ErrorCode::Internal, "internal error")
        }
    }
}

/// Bearer auth: `Authorization: Bearer <token>`, validated per ADR-0003 §3.
/// Returns the token's device — the sender/participant identity the store
/// stamps (never a client-claimed one, ADR-0005 §1).
async fn bearer_device(state: &AppState, headers: &HeaderMap) -> Result<DeviceId, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| error_response(ErrorCode::Unauthorized, "unauthorized"))?;
    auth::validate_token(&state.pool, token)
        .await
        .map_err(auth_error)
}

/// `POST /v1/groups/{gid}/messages` — persist + sequence one MLS message
/// (ADR-0005 §1). Idempotent under retry: a replay returns the original
/// assignment with 200 and does NOT fan out again.
async fn submit_message(
    State(state): State<AppState>,
    Path(gid): Path<GroupId>,
    headers: HeaderMap,
    Json(req): Json<SubmitMessageRequest>,
) -> Result<Json<SubmitMessageResponse>, ApiError> {
    let device = bearer_device(&state, &headers).await?;
    match store::submit_message(&state.pool, device, gid, req)
        .await
        .map_err(store_error)?
    {
        SubmitOutcome::Created(response, envelope) => {
            // AFTER commit only: SendError means zero live subscribers,
            // which is fine — GET sync is the catch-up path.
            let _ = state.fanout.send((gid, Arc::new(envelope)));
            Ok(Json(response))
        }
        // No fanout: the original submit already did.
        SubmitOutcome::Replayed(response) => Ok(Json(response)),
    }
}

#[derive(Deserialize)]
struct AfterQuery {
    after: Option<u64>,
}

/// `GET /v1/groups/{gid}/messages?after=<seq>` — ciphertext sync. The cursor
/// IS the seq (ADR-0005 §1: authoritative, gap-free, monotonic per group;
/// opaque cursor rejected). Bearer-authenticated only: the ADR pins no
/// participant check for the read path — ciphertext is useless to a
/// non-member (INV-1) and membership is client-verified (INV-4).
async fn fetch_messages(
    State(state): State<AppState>,
    Path(gid): Path<GroupId>,
    headers: HeaderMap,
    Query(q): Query<AfterQuery>,
) -> Result<Json<MessagesPage>, ApiError> {
    bearer_device(&state, &headers).await?;
    // Clamp instead of `as i64`: a huge `after` must page to empty, not wrap
    // negative and dump the whole group.
    let after = i64::try_from(q.after.unwrap_or(0)).unwrap_or(i64::MAX);
    let page = store::fetch_messages(&state.pool, gid, after)
        .await
        .map_err(store_error)?;
    Ok(Json(page))
}

/// `GET /v1/gateway` — WebSocket upgrade. The bearer token is validated on
/// the upgrade request BEFORE any socket exists: failure is a plain 401
/// ErrorResponse, not a WS close frame (ADR-0005 §1).
async fn gateway_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let device = bearer_device(&state, &headers).await?;
    Ok(ws.on_upgrade(move |socket| gateway::run(socket, state, device)))
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(health_body()))
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    // Ready means the database answers; startup migrations have already run
    // by the time the router serves.
    match sqlx::query("SELECT 1 AS one").fetch_one(&state.pool).await {
        Ok(_) => (StatusCode::OK, Json(health_body())),
        Err(e) => {
            tracing::error!(error = %e, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "unavailable", "service": "delivery-service"})),
            )
        }
    }
}

fn health_body() -> Value {
    json!({
        "status": "ok",
        "service": "delivery-service",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_body_names_service() {
        let body = health_body();
        assert_eq!(body["service"], "delivery-service");
        assert_eq!(body["status"], "ok");
    }
}
