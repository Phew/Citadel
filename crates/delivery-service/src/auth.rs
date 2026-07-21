//! Bearer-token validation (ADR-0003 §3), replicated against the shared
//! `citadel` database whose `auth_tokens`/`devices` tables are owned by
//! auth-service's migrations.
//!
//! Semantics mirror auth-service exactly: the wire token is base64url
//! (no-pad) of 32 raw bytes; at rest there is only SHA-256(token) (facade
//! `sha256` — the ONLY crypto this crate links, AGENTS.md rule 6). A token
//! is valid iff unexpired, not revoked, and its device has
//! `revoked_at IS NULL`; every failure — malformed, unknown, expired,
//! revoked — collapses to `unauthorized` at the edge (ADR-0003 §1).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use citadel_proto::ids::DeviceId;
use citadel_service_crypto as crypto;
use sqlx::{PgPool, Row};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// Malformed/unknown/expired/revoked token or revoked device — all
    /// collapse to `unauthorized` (ADR-0003 §1).
    #[error("unauthorized")]
    Unauthorized,
}

/// Validate a bearer token; returns its device on success (ADR-0003 §3).
pub async fn validate_token(pool: &PgPool, token: &str) -> Result<DeviceId, AuthError> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| AuthError::Unauthorized)?;
    let raw: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Unauthorized)?;
    let token_hash = crypto::sha256(&raw);

    let row = sqlx::query(
        "SELECT t.device_id FROM auth_tokens t \
         JOIN devices d ON d.id = t.device_id \
         WHERE t.token_hash = $1 \
           AND t.revoked_at IS NULL \
           AND t.expires_at > now() \
           AND d.revoked_at IS NULL",
    )
    .bind(&token_hash[..])
    .fetch_optional(pool)
    .await?;

    row.map(|r| DeviceId::from_uuid(r.get("device_id")))
        .ok_or(AuthError::Unauthorized)
}
