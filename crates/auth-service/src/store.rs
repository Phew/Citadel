//! KeyPackage one-time pool (PLAN.md §6, §8; F1).
//!
//! The pool hands each stored package to exactly one caller, ever, under
//! arbitrary concurrent load. The mechanism is the classic PostgreSQL queue
//! pattern: `SELECT ... FOR UPDATE SKIP LOCKED` inside a transaction that
//! marks `consumed_at` before commit. A concurrent consumer skips locked
//! rows and takes the next available one; a row is re-offered only if its
//! consumer rolls back.
//!
//! Account-level fetch (F2 DM creation: "fetch one unconsumed KeyPackage
//! per target device") is all-or-nothing: if any active device of the
//! account has an empty pool, the whole fetch rolls back so no other
//! device's package is burned on a fetch the caller cannot complete.

use citadel_proto::ids::{AccountId, DeviceId};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// All-or-nothing account fetch found no unconsumed package for this
    /// device. Maps to ErrorCode::KeyPackageUnavailable at the HTTP edge.
    #[error("no unconsumed KeyPackage for device {0}")]
    PoolExhausted(DeviceId),
}

/// A package taken out of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedPackage {
    pub device_id: DeviceId,
    pub package_bytes: Vec<u8>,
}

/// Apply the committed migrations to `pool`. Migrations are the only schema
/// source (no init.sql duplication beyond the M0 sentinel). They are
/// EMBEDDED at compile time: the release binary migrates at startup inside
/// a container that has no source tree, so a runtime path lookup would be
/// a startup crash (first compose-smoke run of the F1 endpoints failed on
/// exactly that).
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Add packages to a device's pool; returns the unconsumed pool size after
/// the insert (PublishKeyPackagesResponse.pool_size).
pub async fn publish(
    pool: &PgPool,
    device_id: DeviceId,
    packages: &[Vec<u8>],
) -> Result<u32, StoreError> {
    if !packages.is_empty() {
        sqlx::query(
            "INSERT INTO key_packages (device_id, package_bytes) \
             SELECT $1, pkg FROM UNNEST($2::bytea[]) AS pkg",
        )
        .bind(device_id.as_uuid())
        .bind(packages)
        .execute(pool)
        .await?;
    }
    unconsumed_count(pool, device_id).await
}

/// Unconsumed pool size for one device.
pub async fn unconsumed_count(pool: &PgPool, device_id: DeviceId) -> Result<u32, StoreError> {
    let row = sqlx::query(
        "SELECT count(*)::bigint AS n FROM key_packages \
         WHERE device_id = $1 AND consumed_at IS NULL",
    )
    .bind(device_id.as_uuid())
    .fetch_one(pool)
    .await?;
    let n: i64 = row.get("n");
    Ok(n as u32)
}

/// Take the oldest unconsumed package for one device, in its own
/// transaction. Returns `None` when the pool is empty.
///
/// `FOR UPDATE SKIP LOCKED` is the exactness mechanism: under concurrency,
/// a row being consumed by another transaction is skipped (never handed out
/// twice), and the lock is held until `consumed_at` commits.
pub async fn consume_one(
    pool: &PgPool,
    device_id: DeviceId,
) -> Result<Option<ConsumedPackage>, StoreError> {
    let mut tx = pool.begin().await?;
    let found = consume_one_in(&mut tx, device_id).await?;
    match found {
        Some(pkg) => {
            tx.commit().await?;
            Ok(Some(pkg))
        }
        None => {
            tx.rollback().await?;
            Ok(None)
        }
    }
}

/// Fetch one unconsumed package per active device of the account,
/// all-or-nothing (see module docs). Order is deterministic by device id.
pub async fn consume_for_account(
    pool: &PgPool,
    account_id: AccountId,
) -> Result<Vec<ConsumedPackage>, StoreError> {
    let mut tx = pool.begin().await?;
    let devices = sqlx::query(
        "SELECT id FROM devices WHERE account_id = $1 AND revoked_at IS NULL ORDER BY id",
    )
    .bind(account_id.as_uuid())
    .fetch_all(&mut *tx)
    .await?;

    let mut out = Vec::with_capacity(devices.len());
    for row in &devices {
        let device_id = DeviceId::from_uuid(row.get("id"));
        match consume_one_in(&mut tx, device_id).await? {
            Some(pkg) => out.push(pkg),
            None => {
                // All-or-nothing: burn nothing if the fetch can't complete.
                tx.rollback().await?;
                return Err(StoreError::PoolExhausted(device_id));
            }
        }
    }
    tx.commit().await?;
    Ok(out)
}

/// Shared core: lock, mark, and return the oldest available package for a
/// device inside an open transaction.
async fn consume_one_in(
    tx: &mut Transaction<'_, Postgres>,
    device_id: DeviceId,
) -> Result<Option<ConsumedPackage>, StoreError> {
    let row = sqlx::query(
        "SELECT id, package_bytes FROM key_packages \
         WHERE device_id = $1 AND consumed_at IS NULL \
         ORDER BY id LIMIT 1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(device_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let id: i64 = row.get("id");
    let package_bytes: Vec<u8> = row.get("package_bytes");

    sqlx::query("UPDATE key_packages SET consumed_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(Some(ConsumedPackage {
        device_id,
        package_bytes,
    }))
}
