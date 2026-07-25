-- ADR-0001 §4 (rev 2): insert-only key-transparency persistence.
--
-- kt_leaves is the append-only leaf source: rebuilt into the in-memory
-- hash tree at startup, the sole input to inclusion-proof generation and
-- the startup root check. `seq` is BIGSERIAL (1-based); the RFC 6962 leaf
-- index is 0-based, so leaf index = seq - 1 (auth-service owns that
-- mapping and pins it in a test).
--
-- kt_sth holds every signed tree head ever issued, keyed by tree size, so
-- a restarted log serves consistency proofs between an old client-pinned
-- STH and a newer one WITHOUT re-signing history (a re-signed divergent
-- head is an equivocation, INV-4). STHs are served from this table, never
-- re-signed on read. `key_id` (per the ADR-0001 rev-2 header note) names
-- the anchor that signed the head, now that the key_id-carrying STH is on
-- main (PR #7).
--
-- Both tables are insert-only: no UPDATE/DELETE in normal operation (an
-- operational purge is an out-of-band, audited action, not a code path).
-- A leaf append and the STH covering it commit in ONE transaction, so
-- kt_sth never lags or leads kt_leaves across a crash.

CREATE TABLE kt_leaves (
    seq        BIGSERIAL PRIMARY KEY,
    leaf_bytes BYTEA NOT NULL -- KtLeaf::leaf_bytes(), the signed pre-image
);

CREATE TABLE kt_sth (
    tree_size  BIGINT PRIMARY KEY,
    key_id     BYTEA NOT NULL CHECK (octet_length(key_id) = 32),
    root_hash  BYTEA NOT NULL CHECK (octet_length(root_hash) = 32),
    signed_at  TIMESTAMPTZ NOT NULL,
    signature  BYTEA NOT NULL CHECK (octet_length(signature) = 64)
);
