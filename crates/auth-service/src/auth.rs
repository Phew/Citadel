//! Challenge-response and bearer-token store (ADR-0003 §1–§3).
//!
//! Challenges: 32 bytes from the OS CSPRNG via the facade (INV-9),
//! single-use, 120 s TTL, at most one outstanding per device. Any verify
//! attempt consumes the challenge, success or failure (anti-replay); an
//! expired or missing challenge is `unauthorized`.
//!
//! Tokens: opaque bearer, 32 CSPRNG bytes, base64url (no-pad) on the wire,
//! stored as SHA-256(token) only — a database leak discloses no usable
//! token. TTL 24 h; renewal is a fresh challenge-response.
//!
//! Revocation (ADR-0003 §3): token validation joins `devices`; a token is
//! valid iff unexpired, not revoked, and its device has `revoked_at IS
//! NULL`. Device revocation and account suspension (one administrative
//! write revoking all of the account's devices) therefore kill tokens
//! immediately, on the unchanged per-request validation path.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use citadel_proto::auth::challenge_signing_input;
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_service_crypto as crypto;
use sqlx::{PgPool, Row};
use thiserror::Error;

/// ADR-0003 §1.
pub const CHALLENGE_TTL_SECS: i64 = 120;
/// ADR-0003 §2.
pub const TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("crypto facade error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    /// Missing/expired/consumed challenge, challenge mismatch, bad
    /// signature, unknown or revoked device, malformed/unknown/expired
    /// token — all collapse to `unauthorized` at the edge (ADR-0003 §1).
    #[error("unauthorized")]
    Unauthorized,
}

/// A freshly issued challenge (ADR-0003 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub challenge: [u8; 32],
    /// Unix seconds.
    pub expires_at: i64,
}

/// A freshly issued bearer token (ADR-0003 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    /// base64url (no-pad) encoding of the raw 32-byte token. The raw bytes
    /// leave the server only here; at rest there is only SHA-256(token).
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Issue a challenge for a device, replacing any outstanding one
/// (ADR-0003 §1). Unknown or revoked devices get `unauthorized` — no
/// oracle on device existence beyond what the verify step already gives.
pub async fn issue_challenge(
    pool: &PgPool,
    device_id: DeviceId,
) -> Result<IssuedChallenge, AuthError> {
    let device = sqlx::query("SELECT 1 AS one FROM devices WHERE id = $1 AND revoked_at IS NULL")
        .bind(device_id.as_uuid())
        .fetch_optional(pool)
        .await?;
    if device.is_none() {
        return Err(AuthError::Unauthorized);
    }

    let challenge = crypto::random_array::<32>()?;
    let expires_at = now_epoch() + CHALLENGE_TTL_SECS;
    sqlx::query(
        "INSERT INTO auth_challenges (device_id, challenge, expires_at) \
         VALUES ($1, $2, to_timestamp($3::float8)) \
         ON CONFLICT (device_id) DO UPDATE \
         SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at",
    )
    .bind(device_id.as_uuid())
    .bind(&challenge[..])
    .bind(expires_at as f64)
    .execute(pool)
    .await?;

    Ok(IssuedChallenge {
        challenge,
        expires_at,
    })
}

/// Verify a challenge answer and, on success, issue a token.
///
/// Consumption semantics (ADR-0003 §1): the challenge row is deleted on
/// ANY attempt and that deletion commits even when verification fails —
/// replay of a consumed challenge is `unauthorized`.
pub async fn verify_challenge_and_issue_token(
    pool: &PgPool,
    device_id: DeviceId,
    challenge: &[u8],
    signature: &[u8; 64],
) -> Result<IssuedToken, AuthError> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        "SELECT challenge, EXTRACT(EPOCH FROM expires_at)::bigint AS expires_epoch \
         FROM auth_challenges WHERE device_id = $1 FOR UPDATE",
    )
    .bind(device_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Err(AuthError::Unauthorized);
    };

    // Anti-replay: consume now; the consumption commits on every path.
    sqlx::query("DELETE FROM auth_challenges WHERE device_id = $1")
        .bind(device_id.as_uuid())
        .execute(&mut *tx)
        .await?;

    let stored: Vec<u8> = row.get("challenge");
    let expires_epoch: i64 = row.get("expires_epoch");
    if expires_epoch <= now_epoch() || stored != challenge {
        tx.commit().await?;
        return Err(AuthError::Unauthorized);
    }

    let device =
        sqlx::query("SELECT device_pubkey FROM devices WHERE id = $1 AND revoked_at IS NULL")
            .bind(device_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await?;
    let Some(device) = device else {
        tx.commit().await?;
        return Err(AuthError::Unauthorized);
    };
    let pubkey_bytes: Vec<u8> = device.get("device_pubkey");
    let pubkey: &[u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .expect("devices.device_pubkey is CHECK-constrained to 32 bytes");

    let input = challenge_signing_input(device_id, challenge);
    if crypto::verify(pubkey, &input, signature).is_err() {
        tx.commit().await?;
        return Err(AuthError::Unauthorized);
    }

    let token = crypto::random_array::<32>()?;
    let token_hash = crypto::sha256(&token);
    let expires_at = now_epoch() + TOKEN_TTL_SECS;
    sqlx::query(
        "INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at) \
         VALUES ($1, $2, to_timestamp($3::float8), to_timestamp($4::float8))",
    )
    .bind(&token_hash[..])
    .bind(device_id.as_uuid())
    .bind(now_epoch() as f64)
    .bind(expires_at as f64)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(IssuedToken {
        token: URL_SAFE_NO_PAD.encode(token),
        expires_at,
    })
}

/// Validate a bearer token; returns its device on success.
///
/// ADR-0003 §3: valid iff the token is unexpired, not revoked, and its
/// device has `revoked_at IS NULL` — device revocation and account
/// suspension (which sets `devices.revoked_at`) kill tokens immediately on
/// this unchanged per-request path.
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

/// Revoke a device (ADR-0003 §3). Its tokens die on the next validation
/// via the join; no token-table write is needed.
pub async fn revoke_device(pool: &PgPool, device_id: DeviceId) -> Result<(), AuthError> {
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(device_id.as_uuid())
        .execute(pool)
        .await?;
    Ok(())
}

/// Suspend an account: one administrative write revoking every device of
/// the account, so all of its tokens die on the same immediate semantics
/// (ADR-0003 §3). Returns the number of devices revoked.
pub async fn suspend_account(pool: &PgPool, account_id: AccountId) -> Result<u64, AuthError> {
    let result = sqlx::query(
        "UPDATE devices SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL",
    )
    .bind(account_id.as_uuid())
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
