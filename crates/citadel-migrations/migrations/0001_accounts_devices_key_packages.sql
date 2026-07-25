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
