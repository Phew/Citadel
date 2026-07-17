-- M0 bootstrap schema placeholder.
-- Real tables land with service migrations in M1+ (sqlx).
-- This file ensures the init mount works and documents intent.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Sentinel so ops can confirm init ran.
CREATE TABLE IF NOT EXISTS citadel_schema_meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);

INSERT INTO citadel_schema_meta (key, value)
VALUES ('m0_init', 'ok')
ON CONFLICT (key) DO NOTHING;
