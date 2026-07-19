//! Account registration (ADR-0003 §6, ADR-0001 §4(b)).
//!
//! Registration is unauthenticated — no prior credential exists — and is
//! the only unauthenticated write besides challenge issuance. Handles are
//! 1–64 bytes of UTF-8, display metadata only: no uniqueness enforcement
//! (identity is `account_id` bound in the KT log; uniqueness would create
//! an enumeration oracle).
//!
//! The registration write is atomic: account row, device row, KT leaf, and
//! the STH covering the leaf commit in ONE transaction (ADR-0001 §4(b)),
//! with the log mutex held across it so the in-memory index and the
//! database `seq` cannot drift.

use citadel_proto::auth::{RegisterAccountRequest, RegisterAccountResponse};
use citadel_proto::kt::KtLeaf;
use citadel_service_crypto as crypto;
use sqlx::PgPool;
use thiserror::Error;

use crate::kt_store::{self, KtState, KtStoreError};

/// ADR-0003 §6 (also keeps `KtLeaf::leaf_bytes()` far from its u16-prefix
/// wrap, docs/issues/004 F3).
pub const HANDLE_MAX_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("kt store error: {0}")]
    Kt(#[from] KtStoreError),
    /// Handle outside 1–64 bytes, or request/credential inconsistency.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// The first-device credential signature does not verify.
    #[error("unauthorized")]
    Unauthorized,
    /// `account_id` or `device_id` is already registered.
    #[error("conflict")]
    Conflict,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Register an account with its first device, appending the identity-key
/// leaf to the KT log in the same transaction.
pub async fn register_account(
    pool: &PgPool,
    kt: &KtState,
    req: &RegisterAccountRequest,
) -> Result<RegisterAccountResponse, RegisterError> {
    let handle_bytes = req.handle.as_bytes();
    if handle_bytes.is_empty() || handle_bytes.len() > HANDLE_MAX_BYTES {
        return Err(RegisterError::InvalidRequest(
            "handle must be 1-64 bytes of UTF-8",
        ));
    }

    let tbs = &req.first_device.tbs;
    if tbs.identity_pubkey != req.identity_pubkey {
        return Err(RegisterError::InvalidRequest(
            "first_device identity_pubkey does not match the request identity_pubkey",
        ));
    }
    crypto::verify(
        &req.identity_pubkey.0,
        &tbs.signing_input(),
        &req.first_device.signature.0,
    )
    .map_err(|_| RegisterError::Unauthorized)?;

    // Hold the log lock across the whole write: in-memory append, signing,
    // and the DB transaction are one serialized unit. The in-memory log is
    // published only after the transaction commits, so a failed
    // registration leaves the log untouched.
    let mut log = kt.log.lock().await;
    let mut working = log.clone();
    let leaf = KtLeaf {
        account_id: tbs.account_id,
        handle: req.handle.clone(),
        identity_pubkey: req.identity_pubkey,
        appended_at: now_epoch(),
    };
    let leaf_index = working.append(&leaf);
    let sth = kt.signer.sign_head(&working, leaf.appended_at);
    let leaf_bytes = leaf.leaf_bytes();

    let mut tx = pool.begin().await?;

    let account = sqlx::query(
        "INSERT INTO accounts (id, handle, identity_pubkey) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tbs.account_id.as_uuid())
    .bind(&req.handle)
    .bind(&req.identity_pubkey.0[..])
    .execute(&mut *tx)
    .await?;
    if account.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(RegisterError::Conflict);
    }

    // The stored credential is the canonical signed form: TBS signing input
    // (deterministic, domain-separated) || the 64-byte identity signature.
    let mut credential_bytes = tbs.signing_input();
    credential_bytes.extend_from_slice(&req.first_device.signature.0);
    let device = sqlx::query(
        "INSERT INTO devices (id, account_id, device_pubkey, credential) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
    )
    .bind(tbs.device_id.as_uuid())
    .bind(tbs.account_id.as_uuid())
    .bind(&tbs.device_pubkey.0[..])
    .bind(&credential_bytes)
    .execute(&mut *tx)
    .await?;
    if device.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(RegisterError::Conflict);
    }

    kt_store::append_leaf_and_sth_in(&mut tx, &leaf_bytes, leaf_index, &sth).await?;
    tx.commit().await?;

    *log = working;
    Ok(RegisterAccountResponse {
        account_id: tbs.account_id,
        device_id: tbs.device_id,
        kt_leaf_index: leaf_index,
        // The client needs the server-assigned timestamp to rebuild its own
        // leaf for the F1 step-5 self-inclusion check (it is part of
        // KtLeaf::leaf_bytes()); report the exact value we appended.
        kt_appended_at: leaf.appended_at,
        kt_tree_head: sth,
    })
}
