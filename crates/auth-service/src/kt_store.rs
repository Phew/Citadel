//! KT log persistence (ADR-0001 §4): insert-only leaves and tree heads.
//!
//! `kt_leaves` is the append-only leaf source; the in-memory [`KtLog`] is
//! rebuilt from it at startup and is the proof engine. `kt_sth` holds every
//! signed tree head ever issued so consistency proofs against old
//! client-pinned heads are served WITHOUT re-signing history (§4(d): STHs
//! are served from the table, never re-signed on read). A leaf append and
//! the STH covering it commit in one transaction (§4(b)). The startup
//! check (§4(c)) is [`rebuild_and_verify`]: a rebuilt root that disagrees
//! with the persisted STH is fatal.

use citadel_proto::credential::Signature;
use citadel_proto::kt::{KeyId, KtHash, SignedTreeHead, TreeHeadTbs};
use kt_log::KtLog;
use sqlx::{PgPool, Row};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KtStoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// §4(c): the tree rebuilt from `kt_leaves` does not match the persisted
    /// STH — tamper or partial write. Startup MUST fail on this.
    #[error(
        "KT startup check failed: rebuilt state (size {rebuilt_size}) does not match \
         persisted kt_sth at tree_size {sth_size} (tamper or partial write)"
    )]
    RootMismatch { rebuilt_size: u64, sth_size: u64 },
    /// The database-assigned `seq` does not map to the in-memory leaf index
    /// (leaf index = seq - 1); DB and log have drifted. The append rolled
    /// back; this is an operator-level alarm, not a client error.
    #[error("KT append mismatch: database assigned seq {seq} but the log expected leaf index {expected_index}")]
    SeqMismatch { seq: i64, expected_index: u64 },
}

/// All leaf bytes in `seq` order — the rebuild input (§4(c)).
pub async fn load_leaves(pool: &PgPool) -> Result<Vec<Vec<u8>>, KtStoreError> {
    let rows = sqlx::query("SELECT leaf_bytes FROM kt_leaves ORDER BY seq")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(|r| r.get("leaf_bytes")).collect())
}

/// The STH at `tree_size`, or the latest when `None`. Served, never
/// re-signed (§4(d)).
pub async fn load_sth(
    pool: &PgPool,
    tree_size: Option<u64>,
) -> Result<Option<SignedTreeHead>, KtStoreError> {
    const COLS: &str = "SELECT tree_size, key_id, root_hash, \
         EXTRACT(EPOCH FROM signed_at)::bigint AS ts, signature FROM kt_sth";
    let row = match tree_size {
        Some(n) => {
            sqlx::query(&format!("{COLS} WHERE tree_size = $1"))
                .bind(n as i64)
                .fetch_optional(pool)
                .await?
        }
        None => {
            sqlx::query(&format!("{COLS} ORDER BY tree_size DESC LIMIT 1"))
                .fetch_optional(pool)
                .await?
        }
    };
    Ok(row.map(|r| sth_from_row(&r)))
}

fn sth_from_row(r: &sqlx::postgres::PgRow) -> SignedTreeHead {
    let key_id: Vec<u8> = r.get("key_id");
    let root_hash: Vec<u8> = r.get("root_hash");
    let signature: Vec<u8> = r.get("signature");
    let tree_size: i64 = r.get("tree_size");
    SignedTreeHead {
        tbs: TreeHeadTbs {
            key_id: KeyId(
                key_id
                    .as_slice()
                    .try_into()
                    .expect("kt_sth.key_id is CHECK-constrained to 32 bytes"),
            ),
            tree_size: tree_size as u64,
            root_hash: KtHash(
                root_hash
                    .as_slice()
                    .try_into()
                    .expect("kt_sth.root_hash is CHECK-constrained to 32 bytes"),
            ),
            timestamp: r.get("ts"),
        },
        signature: Signature(
            signature
                .as_slice()
                .try_into()
                .expect("kt_sth.signature is CHECK-constrained to 64 bytes"),
        ),
    }
}

/// Append a leaf and the STH covering it in ONE transaction (§4(b)), so
/// `kt_sth` never lags or leads `kt_leaves` across a crash.
///
/// `leaf_index` is the index `KtLog::append` returned in memory; the
/// database must assign `seq = leaf_index + 1` (BIGSERIAL is 1-based, the
/// RFC 6962 index is 0-based). Any drift rolls the append back loudly.
/// Returns the assigned `seq`.
pub async fn append_leaf_and_sth(
    pool: &PgPool,
    leaf_bytes: &[u8],
    leaf_index: u64,
    sth: &SignedTreeHead,
) -> Result<i64, KtStoreError> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query("INSERT INTO kt_leaves (leaf_bytes) VALUES ($1) RETURNING seq")
        .bind(leaf_bytes)
        .fetch_one(&mut *tx)
        .await?;
    let seq: i64 = row.get("seq");
    if seq < 1 || (seq - 1) as u64 != leaf_index || sth.tbs.tree_size != leaf_index + 1 {
        tx.rollback().await?;
        return Err(KtStoreError::SeqMismatch {
            seq,
            expected_index: leaf_index,
        });
    }

    sqlx::query(
        "INSERT INTO kt_sth (tree_size, key_id, root_hash, signed_at, signature) \
         VALUES ($1, $2, $3, to_timestamp($4::float8), $5)",
    )
    .bind(sth.tbs.tree_size as i64)
    .bind(&sth.tbs.key_id.0[..])
    .bind(&sth.tbs.root_hash.0[..])
    .bind(sth.tbs.timestamp as f64)
    .bind(&sth.signature.0[..])
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(seq)
}

/// §4(c): rebuild the in-memory log from all `kt_leaves` in `seq` order and
/// verify it against the latest persisted STH. A mismatch (tamper or
/// partial write) is an error the caller MUST treat as fatal to startup.
pub async fn rebuild_and_verify(pool: &PgPool) -> Result<KtLog, KtStoreError> {
    let leaves = load_leaves(pool).await?;
    let log = KtLog::from_leaf_bytes(leaves.iter().map(Vec::as_slice));
    if let Some(sth) = load_sth(pool, None).await? {
        if sth.tbs.tree_size != log.size() || sth.tbs.root_hash.0 != log.root() {
            return Err(KtStoreError::RootMismatch {
                rebuilt_size: log.size(),
                sth_size: sth.tbs.tree_size,
            });
        }
    }
    Ok(log)
}
