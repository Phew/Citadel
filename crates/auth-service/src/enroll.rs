//! Device enrollment (ADR-0004): `POST /v1/devices`.
//!
//! Enrollment is AUTHENTICATED — bearer token from a live existing device
//! (ADR-0003 §3) plus a `DeviceEndorsement` by that same device over the
//! exact new-credential bytes — and deliberately thin: acceptance checks
//! (§1–§3), one `devices` INSERT with `ON CONFLICT` → 409 (§5), and NO KT
//! append (the log attests account identity keys; a second device chains
//! to the identity by signature). New-device proof-of-possession is
//! deferred by design (§4): a key the enroller does not hold is inert —
//! it can never complete the ADR-0003 §1 challenge-response.

use citadel_proto::auth::{EnrollDeviceRequest, EnrollDeviceResponse};
use citadel_proto::credential::endorsement_signing_input;
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_service_crypto as crypto;
use sqlx::{PgPool, Row};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnrollError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// Signature failures (identity signature, endorsement signature),
    /// identity_pubkey mismatch — all collapse to `unauthorized`
    /// (ADR-0003 §1 pattern, ADR-0004 §1/§3).
    #[error("unauthorized")]
    Unauthorized,
    /// Endorsement not by the calling device, or account binding violation
    /// (ADR-0004 §1/§2).
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// `device_id` already enrolled (ADR-0004 §5).
    #[error("conflict")]
    Conflict,
}

/// Enroll a new device for the calling device's account.
///
/// `token_device` is the device `validate_token` authenticated (ADR-0004
/// §1: the bearer token proves a live, unrevoked existing device). All
/// §1–§3 checks run before the single INSERT (§5).
pub async fn enroll_device(
    pool: &PgPool,
    token_device: DeviceId,
    req: &EnrollDeviceRequest,
) -> Result<EnrollDeviceResponse, EnrollError> {
    // §1: the endorsement must be by the calling device itself.
    if req.endorsement.endorsing_device_id != token_device {
        return Err(EnrollError::Forbidden(
            "endorsement must be by the calling device",
        ));
    }

    // Load the endorsing (calling) device: its account and its key. The
    // token already proved it is live and unrevoked (ADR-0003 §3).
    let endorser = sqlx::query(
        "SELECT account_id, device_pubkey FROM devices WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(token_device.as_uuid())
    .fetch_optional(pool)
    .await?
    .ok_or(EnrollError::Unauthorized)?;
    let token_account = AccountId::from_uuid(endorser.get("account_id"));
    let endorser_pubkey: Vec<u8> = endorser.get("device_pubkey");

    // §1: verify the endorsement over the exact credential bytes (commits
    // to the full TBS and its identity signature) with the calling
    // device's key. A stolen token alone cannot enroll.
    let endorser_pubkey: &[u8; 32] = endorser_pubkey
        .as_slice()
        .try_into()
        .expect("devices.device_pubkey is CHECK-constrained to 32 bytes");
    crypto::verify(
        endorser_pubkey,
        &endorsement_signing_input(&req.credential),
        &req.endorsement.signature.0,
    )
    .map_err(|_| EnrollError::Unauthorized)?;

    // §2: a device enrolls only for its own account.
    let tbs = &req.credential.tbs;
    if tbs.account_id != token_account {
        return Err(EnrollError::Forbidden(
            "a device enrolls only for its own account",
        ));
    }

    // §3: the credential binds to the account's KT-attested identity key,
    // and the identity key authorized this binding.
    let account = sqlx::query("SELECT identity_pubkey FROM accounts WHERE id = $1")
        .bind(tbs.account_id.as_uuid())
        .fetch_optional(pool)
        .await?
        .ok_or(EnrollError::Unauthorized)?;
    let identity_pubkey: Vec<u8> = account.get("identity_pubkey");
    if identity_pubkey.as_slice() != tbs.identity_pubkey.0 {
        return Err(EnrollError::Unauthorized);
    }
    crypto::verify(
        &tbs.identity_pubkey.0,
        &tbs.signing_input(),
        &req.credential.signature.0,
    )
    .map_err(|_| EnrollError::Unauthorized)?;

    // §5: one INSERT, ON CONFLICT → 409. The stored credential is the
    // canonical signed form: TBS signing input || identity signature
    // (same convention as registration). NO KT append — enrollment does
    // not take the log mutex.
    let mut credential_bytes = tbs.signing_input();
    credential_bytes.extend_from_slice(&req.credential.signature.0);
    let inserted = sqlx::query(
        "INSERT INTO devices (id, account_id, device_pubkey, credential) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
    )
    .bind(tbs.device_id.as_uuid())
    .bind(tbs.account_id.as_uuid())
    .bind(&tbs.device_pubkey.0[..])
    .bind(&credential_bytes)
    .execute(pool)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(EnrollError::Conflict);
    }

    Ok(EnrollDeviceResponse {
        device_id: tbs.device_id,
    })
}
