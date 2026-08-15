-- Citadel local encrypted client store, application schema v1.
-- ADR-0007 §4 (persistence boundary) and §5 (transaction and crash contract).
--
-- IMMUTABLE AFTER RELEASE. Changing a statement here rather than adding a V2
-- would leave already-created databases silently different from freshly created
-- ones, which no version check would catch.
--
-- Every table in this file lives inside SQLCipher. Plaintext message content,
-- conversation titles, sender metadata, and the exact pending wire bytes are
-- all here on purpose: ADR-0007 §4 puts them inside the encrypted database and
-- keeps the account identity and device signing seeds out of it, in their own
-- OS credential-store entries.

-- Store identity: sentinel, codec identifier, bound-version tuple, schema
-- version. Written before the first OpenMLS record (ADR-0007 §1).
CREATE TABLE citadel_store_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

-- Conversations. `last_epoch` is a cache of the group's durable epoch for
-- listing; MlsGroup's persisted state remains authoritative.
CREATE TABLE citadel_conversations (
    group_id   BLOB PRIMARY KEY NOT NULL,
    created_at INTEGER NOT NULL,
    title      TEXT,
    last_epoch INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Decrypted local message history.
--
-- ADR-0007 §6 is explicit that these rows are NOT covered by the forward-
-- secrecy claim: a compromise holding the database encryption key reads them.
-- Making retained history unreadable is a retention feature needing its own
-- accepted design, not forward secrecy.
--
-- `dedup_key` carries delivery deduplication and is UNIQUE, so a replayed
-- delivery cannot produce a second plaintext row even if the transport retries.
CREATE TABLE citadel_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    BLOB NOT NULL REFERENCES citadel_conversations(group_id) ON DELETE CASCADE,
    direction   TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    epoch       INTEGER NOT NULL,
    sender      BLOB,
    plaintext   BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    dedup_key   BLOB UNIQUE
) STRICT;

CREATE INDEX citadel_messages_by_group ON citadel_messages (group_id, id);

-- Transmissions whose transport outcome is not final: the EXACT wire bytes plus
-- the idempotency key needed to retry without advancing MLS state again.
--
-- ADR-0007 §4: M2 claims no general offline catch-up and no user-facing outbox
-- (both are M5). These rows exist only because persisting an advanced sender
-- ratchet or a pending commit WITHOUT the bytes to retry would be restart-unsafe.
CREATE TABLE citadel_pending_transmissions (
    idempotency_key BLOB PRIMARY KEY NOT NULL,
    group_id        BLOB NOT NULL REFERENCES citadel_conversations(group_id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('application', 'commit', 'welcome')),
    wire_bytes      BLOB NOT NULL,
    proposed_epoch  INTEGER,
    operation_id    BLOB NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX citadel_pending_by_group ON citadel_pending_transmissions (group_id);

-- Delivery sequence cursors and receipts.
CREATE TABLE citadel_delivery_cursors (
    group_id      BLOB PRIMARY KEY NOT NULL REFERENCES citadel_conversations(group_id) ON DELETE CASCADE,
    last_sequence INTEGER NOT NULL
) STRICT;

-- The highest accepted signed KT tree head, for ADR-0001's anti-rollback rule.
-- Single-row by construction: the checkpoint is per profile, not per group.
CREATE TABLE citadel_kt_checkpoint (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    tree_size   INTEGER NOT NULL,
    root_hash   BLOB NOT NULL,
    accepted_at INTEGER NOT NULL
) STRICT;

-- The monotonic per-profile operation sequence (ADR-0007 §5). Single row; the
-- high-water mark never decreases, including across pruning.
CREATE TABLE citadel_operation_sequence (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    high_water INTEGER NOT NULL
) STRICT;

INSERT INTO citadel_operation_sequence (id, high_water) VALUES (1, 0);

-- The unpruned operation-ID ledger, plus a bounded ring of retained outcomes.
--
-- Ledger rows are NEVER pruned: they are what makes a replayed operation ID
-- fail as expired instead of being applied a second time. Only the outcome
-- payload (`outcome_kind`, `outcome_bytes`) is pruned, and only outside the
-- newest 256 sequences. A row whose outcome is NULL is a committed operation
-- whose receipt has expired.
CREATE TABLE citadel_operation_ledger (
    operation_id  BLOB PRIMARY KEY NOT NULL,
    sequence      INTEGER NOT NULL UNIQUE,
    kind          TEXT NOT NULL,
    fingerprint   BLOB NOT NULL,
    outcome_kind  TEXT,
    outcome_bytes BLOB,
    committed_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX citadel_operation_ledger_by_sequence ON citadel_operation_ledger (sequence);
