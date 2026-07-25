-- ADR-0006 evidence fixture for canonical_migrations_upgrade_previous_schema_fixture.
--
-- The pre-0004 applied state: the public schema exactly as migrations
-- 0001-0003 (auth-service, M1) left it, plus their _sqlx_migrations history
-- rows carrying the canonical SHA-384 checksums. GENERATED from the
-- canonical corpus files (0001-0003 SQL verbatim) — never hand-edit the
-- checksums; regenerate from the corpus instead.

-- 0001: auth-service schema — accounts, devices, KeyPackage one-time pool.
-- Shape per PLAN.md §6; everything content-bearing here is public-key
-- material or opaque MLS KeyPackage bytes (never private keys, INV-2;
-- never plaintext content, INV-1). kt_log lands with the KT integration.

CREATE TABLE accounts (
    id              UUID PRIMARY KEY,
    handle          TEXT NOT NULL,
    identity_pubkey BYTEA NOT NULL CHECK (octet_length(identity_pubkey) = 32),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE devices (
    id           UUID PRIMARY KEY,
    account_id   UUID NOT NULL REFERENCES accounts (id),
    device_pubkey BYTEA NOT NULL CHECK (octet_length(device_pubkey) = 32),
    -- Signed DeviceCredential wire bytes; verification happens at enrollment.
    credential   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX devices_account_active
    ON devices (account_id)
    WHERE revoked_at IS NULL;

-- One-time KeyPackage pool (F1 step 4, PLAN.md §8). consumed_at IS NULL means
-- available. Consumption is transactional exactly-once under concurrency
-- (FOR UPDATE SKIP LOCKED; see store::key_packages and the M1 property test).
CREATE TABLE key_packages (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id     UUID NOT NULL REFERENCES devices (id),
    package_bytes BYTEA NOT NULL,
    consumed_at   TIMESTAMPTZ
);

-- The hot consumption path: unconsumed packages per device, in insert order.
CREATE INDEX key_packages_available
    ON key_packages (device_id, id)
    WHERE consumed_at IS NULL;

-- ADR-0003 §1–§2: challenge-response state and bearer tokens.
--
-- auth_challenges: at most one outstanding challenge per device (PK on
-- device_id; a new request replaces the old — natural anti-amplification).
-- Any verify attempt consumes the row, success or failure (anti-replay).
--
-- auth_tokens: the raw bearer token is NEVER stored, only SHA-256(token)
-- (facade sha256) — a database leak discloses no usable token. Revocation
-- has no column here beyond revoked_at: token validation joins devices and
-- requires devices.revoked_at IS NULL, so revoking a device (or suspending
-- an account, which revokes all of its devices in one write) kills its
-- tokens immediately (ADR-0003 §3).

CREATE TABLE auth_challenges (
    device_id  UUID PRIMARY KEY REFERENCES devices (id),
    challenge  BYTEA NOT NULL CHECK (octet_length(challenge) = 32),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE auth_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    device_id  UUID NOT NULL REFERENCES devices (id),
    issued_at  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX auth_tokens_device ON auth_tokens (device_id);

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

-- sqlx's history table at the 0003 head.
CREATE TABLE public._sqlx_migrations (
    version        BIGINT PRIMARY KEY,
    description    TEXT NOT NULL,
    installed_on   TIMESTAMPTZ NOT NULL DEFAULT now(),
    success        BOOLEAN NOT NULL,
    checksum       BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);

INSERT INTO public._sqlx_migrations (version, description, success, checksum, execution_time) VALUES
    (1, 'accounts devices key packages', true, decode('e40e71132731c4b2955722122215c93b7367de40229982c3088376d954dccd7218a6700b0655b8b057af674a008345a8', 'hex'), 0),
    (2, 'auth challenges tokens', true, decode('f1433cc6311705807a3e84cfd635b732375488c56638f560b072d3714c57367508ab51fde5d919fbfbdf97943e1107be', 'hex'), 0),
    (3, 'kt log', true, decode('824397d69a7f6693005d9332117a4bffc3f4ee04b70a05b940a29fb6ea22b8b6a27917886b5e36368b53c7bc9bc11337', 'hex'), 0);
