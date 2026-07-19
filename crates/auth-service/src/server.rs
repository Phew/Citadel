//! HTTP surface (PLAN.md §8): axum router and handlers over the store.
//!
//! Handlers are thin: request validation lives in citadel-proto types,
//! semantics in the store modules. Errors map to the stable wire taxonomy
//! (citadel_proto::error); auth failures always collapse to `unauthorized`
//! (ADR-0003 §1).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use citadel_proto::auth::{ChallengeRequest, ChallengeResponse, VerifyRequest, VerifyResponse};
use citadel_proto::error::{ErrorCode, ErrorResponse};
use citadel_proto::kt::KtProofResponse;
use kt_log::{KtLog, TreeHeadSigner};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;

use crate::auth::{self, AuthError};
use crate::kt_store::{self, KtStoreError};

/// KT log state: the in-memory proof engine (rebuilt from `kt_leaves` at
/// startup, ADR-0001 §4(c)) and the encapsulated tree-head signer
/// (ADR-0001 §3 — auth-service holds the type but cannot sign arbitrary
/// bytes).
pub struct KtState {
    pub log: Mutex<KtLog>,
    pub signer: TreeHeadSigner,
}

/// Shared service state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub kt: Arc<KtState>,
}

/// The auth-service router: health probes, the F1 auth flow, and the KT
/// read surface (PLAN.md §8, ADR-0003 §5, docs/protocol/auth.md §5).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/kt/tree-head", get(kt_tree_head))
        .route("/v1/kt/proof", get(kt_proof))
        .route("/v1/kt/consistency", get(kt_consistency))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn error_response(code: ErrorCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    let status =
        StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorResponse::new(code, message)))
}

fn auth_error(err: AuthError) -> (StatusCode, Json<ErrorResponse>) {
    match err {
        AuthError::Unauthorized => error_response(ErrorCode::Unauthorized, "unauthorized"),
        AuthError::Database(e) => {
            tracing::error!(error = %e, "auth store error");
            error_response(ErrorCode::Internal, "internal error")
        }
        AuthError::Crypto(e) => {
            tracing::error!(error = %e, "crypto facade error");
            error_response(ErrorCode::Internal, "internal error")
        }
    }
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let issued = auth::issue_challenge(&state.pool, req.device_id)
        .await
        .map_err(auth_error)?;
    Ok(Json(ChallengeResponse {
        challenge: issued.challenge.to_vec(),
        expires_at: issued.expires_at,
    }))
}

async fn auth_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let issued = auth::verify_challenge_and_issue_token(
        &state.pool,
        req.device_id,
        &req.challenge,
        &req.signature.0,
    )
    .await
    .map_err(auth_error)?;
    Ok(Json(VerifyResponse {
        token: issued.token,
        expires_at: issued.expires_at,
    }))
}

// ---------- KT read surface (ADR-0001 §4, ADR-0003 §5) ----------

type ApiError = (StatusCode, Json<ErrorResponse>);

fn kt_error(err: KtStoreError) -> ApiError {
    tracing::error!(error = %err, "kt store error");
    error_response(ErrorCode::Internal, "internal error")
}

/// `GET /v1/kt/tree-head` — the latest STH, served from `kt_sth`, never
/// re-signed on read (ADR-0001 §4(d)).
async fn kt_tree_head(
    State(state): State<AppState>,
) -> Result<Json<citadel_proto::kt::SignedTreeHead>, ApiError> {
    kt_store::load_sth(&state.pool, None)
        .await
        .map_err(kt_error)?
        .map(Json)
        .ok_or_else(|| error_response(ErrorCode::NotFound, "KT log is empty"))
}

#[derive(Deserialize)]
struct ProofQuery {
    leaf: u64,
    tree_size: Option<u64>,
}

/// `GET /v1/kt/proof?leaf=<index>[&tree_size=<n>]` — the inclusion proof
/// AND the exact STH it verifies against, one atomic response (ADR-0003 §5:
/// no TOCTOU window between a fetch-proof and a fetch-head call). Default
/// `tree_size` is the latest STH.
async fn kt_proof(
    State(state): State<AppState>,
    Query(q): Query<ProofQuery>,
) -> Result<Json<KtProofResponse>, ApiError> {
    // The STH comes first: the in-memory log is always at least as large as
    // any persisted head (appends commit leaf+STH in one transaction), so
    // the proof below can always be computed for the head we just served.
    let sth = match q.tree_size {
        Some(n) => kt_store::load_sth(&state.pool, Some(n))
            .await
            .map_err(kt_error)?
            .ok_or_else(|| {
                error_response(ErrorCode::NotFound, "no signed tree head at that tree size")
            })?,
        None => kt_store::load_sth(&state.pool, None)
            .await
            .map_err(kt_error)?
            .ok_or_else(|| error_response(ErrorCode::NotFound, "KT log is empty"))?,
    };

    let proof = {
        let log = state.kt.log.lock().expect("kt log mutex poisoned");
        log.inclusion_proof(q.leaf, sth.tbs.tree_size)
    }
    .map_err(|_| {
        error_response(
            ErrorCode::InvalidRequest,
            "leaf index out of range for the requested tree size",
        )
    })?;

    Ok(Json(KtProofResponse {
        proof,
        signed_tree_head: sth,
    }))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

/// `GET /v1/kt/consistency?first=<a>&second=<b>` — RFC 6962 consistency
/// proof between two tree sizes (docs/protocol/auth.md §5). Clients verify
/// it between the STHs they hold; serving it needs only the rebuilt leaves.
async fn kt_consistency(
    State(state): State<AppState>,
    Query(q): Query<ConsistencyQuery>,
) -> Result<Json<citadel_proto::kt::ConsistencyProof>, ApiError> {
    let proof = {
        let log = state.kt.log.lock().expect("kt log mutex poisoned");
        log.consistency_proof(q.first, q.second)
    }
    .map_err(|_| {
        error_response(
            ErrorCode::InvalidRequest,
            "invalid size range: need 0 < first <= second <= current tree size",
        )
    })?;
    Ok(Json(proof))
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
                Json(json!({"status": "unavailable", "service": "auth-service"})),
            )
        }
    }
}

fn health_body() -> Value {
    json!({
        "status": "ok",
        "service": "auth-service",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_body_names_service() {
        let body = health_body();
        assert_eq!(body["service"], "auth-service");
        assert_eq!(body["status"], "ok");
    }
}
