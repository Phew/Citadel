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
