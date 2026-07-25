-- ADR-0005 §2 + Amendment 1: M2 DM delivery — ciphertext-only storage (INV-1).
--
-- Numbering starts at 0004 because auth-service's migrator already recorded
-- versions 0001–0003 in the shared `_sqlx_migrations` table of the `citadel`
-- database. Both services migrate the same database; each migrator runs with
-- `ignore_missing` so the other's rows in `_sqlx_migrations` are tolerated.
--
-- These tables hold opaque MLS bytes plus (group_id, epoch, seq) and
-- addressing metadata ONLY. No plaintext, no decryption path (INV-1). The
-- no-plaintext canary scan covers them (ADR-0005 §2, Evidence).
--
-- groups: one row per MLS group, created LAZILY by the first submit inside
-- the submit transaction (Amendment 1 §A — for a DM the first submit is the
-- founding Welcome). `next_seq` is the per-group serialization point: the
-- submit transaction locks the row `FOR UPDATE`, reads next_seq, assigns
-- next_seq+1, and bumps it, so concurrent submits serialize and seq stays
-- gap-free and monotonic per group (ADR-0005 §1; M3's one-commit-per-epoch
-- enforcement will key off this same point, INV-6 — reserved, not built).
CREATE TABLE groups (
    mls_group_id UUID PRIMARY KEY,
    dm           BOOLEAN NOT NULL DEFAULT true, -- M2 is DMs; channel_id null until M3
    channel_id   UUID,
    next_seq     BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- group_messages: the ciphertext store. `seq` is server-assigned (authoritative,
-- gap-free, monotonic per group); `epoch` is CLIENT-DECLARED, stored and echoed
-- as an ordering hint only — never derived from ciphertext and never trusted
-- (INV-4). `sender_device_id` comes from the validated bearer token, never from
-- a client-claimed envelope field (ADR-0005 §1).
--
-- UNIQUE(mls_group_id, seq) is the backstop under concurrency; the groups-row
-- FOR UPDATE lock is the mechanism. UNIQUE(mls_group_id, idempotency_key)
-- makes offline retry safe: a replay returns the original assignment and
-- inserts nothing (ADR-0005 §1).
CREATE TABLE group_messages (
    id               UUID PRIMARY KEY, -- server-assigned MessageId
    mls_group_id     UUID NOT NULL REFERENCES groups (mls_group_id),
    seq              BIGINT NOT NULL,
    epoch            BIGINT NOT NULL, -- client-declared hint, not trusted (INV-4)
    kind             TEXT NOT NULL CHECK (kind IN ('application', 'proposal', 'commit', 'welcome')),
    sender_device_id UUID, -- from the auth token, never client-claimed
    idempotency_key  UUID NOT NULL,
    payload_bytes    BYTEA NOT NULL, -- opaque MLS bytes; ciphertext only (INV-1)
    server_ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mls_group_id, seq),
    UNIQUE (mls_group_id, idempotency_key)
);

-- welcome_deliveries: F2 Welcome addressing (ADR-0005 §1). Welcomes target
-- specific DEVICES (joiners are not yet subscribed), not the group broadcast.
-- One row per recipient, written in the same transaction as the Welcome's
-- group_messages row. On a recipient's next gateway connect the undelivered
-- rows are pushed as Message frames, then delivered_at is set (at-least-once:
-- a socket dying mid-push leaves rows unmarked, so they redeliver next
-- connect; the client dedups).
CREATE TABLE welcome_deliveries (
    welcome_message_id  UUID NOT NULL REFERENCES group_messages (id),
    recipient_device_id UUID NOT NULL,
    delivered_at        TIMESTAMPTZ,
    PRIMARY KEY (welcome_message_id, recipient_device_id)
);

-- The on-connect undelivered-welcome query filters on
-- (recipient_device_id, delivered_at IS NULL); the PK leads with
-- welcome_message_id and cannot serve it.
CREATE INDEX welcome_deliveries_pending
    ON welcome_deliveries (recipient_device_id)
    WHERE delivered_at IS NULL;
