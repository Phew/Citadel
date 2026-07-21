//! Ciphertext message store (ADR-0005 §1–§2, Amendment 1).
//!
//! Everything here is opaque MLS bytes plus sequencing/addressing metadata:
//! no plaintext, no decryption path (INV-1). The load-bearing pieces:
//!
//! - **seq assignment** is one transaction per submit. The `groups` row is
//!   the per-group serialization point: `SELECT ... FOR UPDATE`, assign
//!   `next_seq + 1`, bump, insert. `UNIQUE(mls_group_id, seq)` is the
//!   backstop; the row lock is the mechanism. M3's one-commit-per-epoch
//!   (INV-6) will key off this same point — reserved, not built here.
//! - **idempotent retry**: `UNIQUE(mls_group_id, idempotency_key)`. A replay
//!   returns the original `(message_id, seq, epoch, server_ts)` and inserts
//!   nothing (ADR-0005 §1). If a concurrent replay races past the pre-check,
//!   the insert's `ON CONFLICT DO NOTHING` returns no row and the whole
//!   transaction ROLLS BACK — which also undoes the `next_seq` bump; that is
//!   exactly what keeps seq gap-free under retry races.
//! - **submit authorization** (Amendment 1 §B): the first submit to a new
//!   gid must be a Welcome (the device founds the group); afterwards the
//!   sender must already be a participant per delivery metadata (sender of a
//!   row in G, or a welcome recipient in G). A rejected first submit returns
//!   BEFORE the groups-row upsert, so it never materializes the row — a
//!   materialized row would permanently lock the gid for the real founder.
//!   This is spam/metadata hygiene, never a security boundary (INV-4 stays
//!   the content authority; INV-1 makes stray ciphertext harmless).
//! - **epoch** is client-declared, stored and echoed as an ordering hint
//!   only. It is never derived from ciphertext and never trusted (INV-4).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use citadel_proto::delivery::{
    MessagesPage, SubmitMessageRequest, SubmitMessageResponse, MESSAGES_PAGE_LIMIT,
};
use citadel_proto::envelope::{Envelope, EnvelopeKind, WIRE_VERSION};
use citadel_proto::ids::{DeviceId, GroupId, MessageId};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    /// Wire-shape violation; maps to ErrorCode::InvalidRequest (400).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Amendment 1 §B participant check failed; maps to ErrorCode::Forbidden
    /// (403). Spam hygiene only, never the security boundary.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Maps to ErrorCode::Unauthorized (401).
    #[error("unauthorized")]
    Unauthorized,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Result of a submit. `Created` carries the fully populated fanout copy of
/// the envelope (seq/epoch/sender stamped); the HTTP layer fans it out AFTER
/// commit. `Replayed` carries the original assignment only — the original
/// submit already fanned out, so a replay must not fan out again.
#[derive(Debug)]
pub enum SubmitOutcome {
    Created(SubmitMessageResponse, Envelope),
    Replayed(SubmitMessageResponse),
}

/// Apply the committed migrations to `pool` (EMBEDDED at compile time; the
/// release binary migrates inside a container with no source tree).
///
/// `ignore_missing` is load-bearing for the shared-database layout:
/// auth-service's migrator records versions 0001–0003 in the same
/// `_sqlx_migrations` table, and sqlx errors with "previously applied but
/// missing" when a migrator sees applied versions outside its own set.
/// Delivery numbering therefore starts at 0004 (a same-version
/// different-checksum clash would be fatal) and both migrators tolerate the
/// other's rows.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.ignore_missing = true;
    migrator.run(pool).await
}

/// The kind TEXT values are pinned by the schema CHECK constraint
/// (`kind IN ('application','proposal','commit','welcome')`); `control`
/// envelopes exist on the wire (proto) but are not storable (ADR-0005 §2).
fn kind_to_text(kind: EnvelopeKind) -> Result<&'static str, StoreError> {
    match kind {
        EnvelopeKind::Application => Ok("application"),
        EnvelopeKind::Proposal => Ok("proposal"),
        EnvelopeKind::Commit => Ok("commit"),
        EnvelopeKind::Welcome => Ok("welcome"),
        EnvelopeKind::Control => Err(StoreError::InvalidRequest(
            "control envelopes are not storable (ADR-0005 §2 kind CHECK)".into(),
        )),
    }
}

fn kind_from_text(text: &str) -> EnvelopeKind {
    match text {
        "application" => EnvelopeKind::Application,
        "proposal" => EnvelopeKind::Proposal,
        "commit" => EnvelopeKind::Commit,
        "welcome" => EnvelopeKind::Welcome,
        // The schema CHECK constraint makes anything else unreachable.
        other => panic!("group_messages.kind is CHECK-constrained; got {other:?}"),
    }
}

/// Unix-milliseconds rendering of a row's server_ts, for the wire contract.
const SERVER_TS_MS_EXPR: &str = "(EXTRACT(EPOCH FROM server_ts) * 1000)::BIGINT";

/// Submit one MLS message to a group (ADR-0005 §1, Amendment 1).
///
/// `authed` is the device from the validated bearer token; the envelope's
/// client-claimed `sender_device_id` is ignored — the server stamps it.
pub async fn submit_message(
    pool: &PgPool,
    authed: DeviceId,
    gid: GroupId,
    req: SubmitMessageRequest,
) -> Result<SubmitOutcome, StoreError> {
    // ---- Pre-transaction wire-shape validation (cheap, stateless). ----
    req.validate()
        .map_err(|m| StoreError::InvalidRequest(m.to_string()))?;
    let env = &req.envelope;
    if env.group_id != Some(gid) {
        return Err(StoreError::InvalidRequest(
            "envelope.group_id must equal the path group id".into(),
        ));
    }
    if !env.version_supported() {
        // INV-5: reject, never silently downgrade.
        return Err(StoreError::InvalidRequest(format!(
            "unsupported wire version {}; this build speaks {WIRE_VERSION}",
            env.version
        )));
    }
    let epoch = env.epoch.ok_or_else(|| {
        // group_messages.epoch is NOT NULL, and ADR-0005 §1 pins the client
        // to always declare its current epoch — reject rather than default.
        StoreError::InvalidRequest("envelope.epoch is required on submit".into())
    })?;
    let kind_text = kind_to_text(env.kind)?;
    // Decode once here and bind the raw bytes; the payload is opaque MLS
    // ciphertext, never parsed (INV-1).
    let payload = env
        .payload_bytes()
        .map_err(|_| StoreError::InvalidRequest("payload_b64 is not valid base64".into()))?;

    let mut tx = pool.begin().await?;

    // ---- (a) Participant authorization, BEFORE any write (Amendment 1 §B).
    // A rejected first submit must return before the groups-row upsert:
    // materializing the row would permanently lock the gid against the real
    // founder's Welcome.
    let group_exists = sqlx::query("SELECT 1 AS one FROM groups WHERE mls_group_id = $1")
        .bind(gid.as_uuid())
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
    if !group_exists {
        if env.kind != EnvelopeKind::Welcome {
            tx.rollback().await?;
            return Err(StoreError::Forbidden(
                "the first submit to a group must be a welcome (Amendment 1 §B)".into(),
            ));
        }
        // Founder: authorized precisely by submitting the founding Welcome.
    } else if !is_participant_in(&mut tx, authed, gid).await? {
        tx.rollback().await?;
        return Err(StoreError::Forbidden(
            "sender is not a participant in this group (Amendment 1 §B)".into(),
        ));
    }

    // ---- (b) Idempotency pre-check: an already-stored submit with this
    // (gid, idempotency_key) returns the ORIGINAL assignment. Nothing was
    // written this transaction, but commit anyway to release the connection
    // on a clean path.
    if let Some(row) = sqlx::query(&format!(
        "SELECT id, seq, epoch, {SERVER_TS_MS_EXPR} AS server_ts_ms \
         FROM group_messages WHERE mls_group_id = $1 AND idempotency_key = $2"
    ))
    .bind(gid.as_uuid())
    .bind(req.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let response = replay_response(&row, gid);
        tx.commit().await?;
        return Ok(SubmitOutcome::Replayed(response));
    }

    // ---- (c) Lazy groups-row creation (Amendment 1 §A). ON CONFLICT DO
    // NOTHING makes concurrent first-submits and retries safe.
    sqlx::query("INSERT INTO groups (mls_group_id, dm) VALUES ($1, true) ON CONFLICT DO NOTHING")
        .bind(gid.as_uuid())
        .execute(&mut *tx)
        .await?;

    // ---- (d) Serialization point: lock the groups row, assign next_seq+1,
    // bump it. Concurrent submits serialize here; seq is gap-free because a
    // rolled-back transaction also rolls back the bump.
    let row = sqlx::query("SELECT next_seq FROM groups WHERE mls_group_id = $1 FOR UPDATE")
        .bind(gid.as_uuid())
        .fetch_one(&mut *tx)
        .await?;
    let next_seq: i64 = row.get("next_seq");
    let seq = next_seq + 1;
    sqlx::query("UPDATE groups SET next_seq = $2 WHERE mls_group_id = $1")
        .bind(gid.as_uuid())
        .bind(seq)
        .execute(&mut *tx)
        .await?;

    // ---- (e) Insert the ciphertext row. If a concurrent replay raced past
    // step (b), this insert conflicts on (mls_group_id, idempotency_key) and
    // returns NO row: ROLLBACK (undoing the seq bump — gap-freedom depends
    // on it) and re-read the winner's assignment fresh.
    let message_id = MessageId::new();
    let inserted = sqlx::query(&format!(
        "INSERT INTO group_messages \
         (id, mls_group_id, seq, epoch, kind, sender_device_id, idempotency_key, payload_bytes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (mls_group_id, idempotency_key) DO NOTHING \
         RETURNING id, {SERVER_TS_MS_EXPR} AS server_ts_ms"
    ))
    .bind(message_id.as_uuid())
    .bind(gid.as_uuid())
    .bind(seq)
    .bind(epoch as i64)
    .bind(kind_text)
    .bind(authed.as_uuid())
    .bind(req.idempotency_key)
    .bind(&payload)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(inserted) = inserted else {
        tx.rollback().await?;
        let row = sqlx::query(&format!(
            "SELECT id, seq, epoch, {SERVER_TS_MS_EXPR} AS server_ts_ms \
             FROM group_messages WHERE mls_group_id = $1 AND idempotency_key = $2"
        ))
        .bind(gid.as_uuid())
        .bind(req.idempotency_key)
        .fetch_one(pool)
        .await?;
        return Ok(SubmitOutcome::Replayed(replay_response(&row, gid)));
    };
    let server_ts: i64 = inserted.get("server_ts_ms");

    // ---- (f) F2 Welcome addressing: one delivery row per recipient device,
    // same transaction as the message row (ADR-0005 §1).
    if env.kind == EnvelopeKind::Welcome {
        let recipients: Vec<uuid::Uuid> = req
            .recipient_device_ids
            .iter()
            .map(|d| d.as_uuid())
            .collect();
        sqlx::query(
            "INSERT INTO welcome_deliveries (welcome_message_id, recipient_device_id) \
             SELECT $1, r FROM UNNEST($2::uuid[]) AS r \
             ON CONFLICT DO NOTHING",
        )
        .bind(message_id.as_uuid())
        .bind(&recipients)
        .execute(&mut *tx)
        .await?;
    }

    // ---- (g) Commit, THEN the caller fans out (never before commit).
    tx.commit().await?;

    let response = SubmitMessageResponse {
        message_id,
        group_id: gid,
        epoch,
        seq: seq as u64,
        server_ts,
    };
    let mut fanout = env.clone();
    fanout.seq = Some(seq as u64);
    fanout.epoch = Some(epoch);
    fanout.sender_device_id = Some(authed);
    Ok(SubmitOutcome::Created(response, fanout))
}

/// The Amendment 1 §B / decision-#5 participant predicate, against an open
/// transaction: sender of some group_messages row in G, or a welcome
/// recipient in G. Metadata-only spam hygiene (INV-1 makes over-inclusion
/// harmless; INV-4 keeps content authority at the client).
async fn is_participant_in(
    tx: &mut Transaction<'_, Postgres>,
    device: DeviceId,
    gid: GroupId,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT (EXISTS(SELECT 1 FROM group_messages \
                        WHERE mls_group_id = $1 AND sender_device_id = $2) \
              OR EXISTS(SELECT 1 FROM welcome_deliveries w \
                        JOIN group_messages m ON m.id = w.welcome_message_id \
                        WHERE m.mls_group_id = $1 AND w.recipient_device_id = $2)) \
                AS participant",
    )
    .bind(gid.as_uuid())
    .bind(device.as_uuid())
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.get("participant"))
}

/// Same participant predicate, outside a transaction (gateway subscribe
/// authorization — decision #5: spam hygiene, never confidentiality).
pub async fn is_participant(
    pool: &PgPool,
    device: DeviceId,
    gid: GroupId,
) -> Result<bool, StoreError> {
    let mut tx = pool.begin().await?;
    let participant = is_participant_in(&mut tx, device, gid).await?;
    tx.commit().await?;
    Ok(participant)
}

/// Build the replay response from a fetched group_messages row.
fn replay_response(row: &sqlx::postgres::PgRow, gid: GroupId) -> SubmitMessageResponse {
    let seq: i64 = row.get("seq");
    let epoch: i64 = row.get("epoch");
    SubmitMessageResponse {
        message_id: MessageId::from_uuid(row.get("id")),
        group_id: gid,
        epoch: epoch as u64,
        seq: seq as u64,
        server_ts: row.get("server_ts_ms"),
    }
}

/// Map a stored row back onto the wire envelope: version pinned to
/// WIRE_VERSION, seq/epoch/sender populated from the row, payload re-encoded
/// as standard base64 (ADR-0005 §1: each synced envelope has
/// seq/epoch/sender_device_id populated).
fn envelope_from_row(row: &sqlx::postgres::PgRow, gid: GroupId) -> Envelope {
    let seq: i64 = row.get("seq");
    let epoch: i64 = row.get("epoch");
    let kind: String = row.get("kind");
    let sender: Option<uuid::Uuid> = row.get("sender_device_id");
    let payload: Vec<u8> = row.get("payload_bytes");
    Envelope {
        version: WIRE_VERSION,
        kind: kind_from_text(&kind),
        group_id: Some(gid),
        epoch: Some(epoch as u64),
        seq: Some(seq as u64),
        sender_device_id: sender.map(DeviceId::from_uuid),
        payload_b64: B64.encode(payload),
    }
}

const MESSAGE_COLUMNS: &str =
    "id, mls_group_id, seq, epoch, kind, sender_device_id, payload_bytes";

/// One page of ciphertext sync (ADR-0005 §1): rows with `seq > after`
/// ascending, at most MESSAGES_PAGE_LIMIT (500). We fetch one extra row to
/// compute `has_more` without a COUNT.
pub async fn fetch_messages(
    pool: &PgPool,
    gid: GroupId,
    after: i64,
) -> Result<MessagesPage, StoreError> {
    let rows = sqlx::query(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM group_messages \
         WHERE mls_group_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3"
    ))
    .bind(gid.as_uuid())
    .bind(after)
    .bind(MESSAGES_PAGE_LIMIT as i64 + 1)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() > MESSAGES_PAGE_LIMIT;
    let rows = &rows[..rows.len().min(MESSAGES_PAGE_LIMIT)];
    let messages: Vec<Envelope> = rows.iter().map(|r| envelope_from_row(r, gid)).collect();
    let next_after = messages
        .last()
        .and_then(|e| e.seq)
        .unwrap_or(after.max(0) as u64);
    Ok(MessagesPage {
        group_id: gid,
        messages,
        next_after,
        has_more,
    })
}

/// Undelivered welcomes addressed to a device, pushed on its next gateway
/// connect (ADR-0005 §1 F2). Served by the partial index
/// `welcome_deliveries_pending` (the PK leads with welcome_message_id and
/// cannot serve the recipient lookup).
pub async fn undelivered_welcomes(
    pool: &PgPool,
    device: DeviceId,
) -> Result<Vec<(MessageId, Envelope)>, StoreError> {
    let rows = sqlx::query(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM welcome_deliveries w \
         JOIN group_messages m ON m.id = w.welcome_message_id \
         WHERE w.recipient_device_id = $1 AND w.delivered_at IS NULL \
         ORDER BY m.server_ts ASC, m.id ASC"
    ))
    .bind(device.as_uuid())
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let gid = GroupId::from_uuid(r.get("mls_group_id"));
            (MessageId::from_uuid(r.get("id")), envelope_from_row(r, gid))
        })
        .collect())
}

/// Mark exactly these welcomes delivered for this device. At-least-once
/// semantics: rows a dead socket never pushed stay NULL and redeliver on the
/// next connect (the client dedups on message id / MLS state).
pub async fn mark_welcomes_delivered(
    pool: &PgPool,
    device: DeviceId,
    welcome_message_ids: &[MessageId],
) -> Result<(), StoreError> {
    let ids: Vec<uuid::Uuid> = welcome_message_ids.iter().map(|m| m.as_uuid()).collect();
    sqlx::query(
        "UPDATE welcome_deliveries SET delivered_at = now() \
         WHERE recipient_device_id = $1 AND welcome_message_id = ANY($2) \
           AND delivered_at IS NULL",
    )
    .bind(device.as_uuid())
    .bind(&ids)
    .execute(pool)
    .await?;
    Ok(())
}
