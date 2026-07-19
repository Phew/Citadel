//! HTTP surface (PLAN.md §8): axum router and handlers over the store.
//!
//! Handlers are thin: request validation lives in citadel-proto types,
//! semantics in the store modules. Errors map to the stable wire taxonomy
//! (citadel_proto::error); auth failures always collapse to `unauthorized`
//! (ADR-0003 §1).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use citadel_proto::auth::{ChallengeRequest, ChallengeResponse, VerifyRequest, VerifyResponse};
use citadel_proto::error::{ErrorCode, ErrorResponse};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::auth::{self, AuthError};

/// Shared service state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

/// The auth-service router: health probes plus the F1 auth flow.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
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
