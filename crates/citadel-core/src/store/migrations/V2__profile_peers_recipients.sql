-- Citadel local encrypted client store, application schema v2.
-- IMMUTABLE AFTER RELEASE (see V1).
--
-- What a running client needs that v1 did not persist: who this profile is
-- (the registered account/device and its KT leaf coordinates), which peers
-- this profile has KT-verified and at what tree size, and the recipient
-- devices of a pending Welcome so a restart can still submit it.

-- Exactly one row: the account and device this profile registered as. The
-- signing seeds stay in the OS credential store (ADR-0007 §4); only public
-- material and the signed credential are here.
CREATE TABLE citadel_profile (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    account_id      BLOB NOT NULL,
    device_id       BLOB NOT NULL,
    handle          TEXT NOT NULL,
    identity_pubkey BLOB NOT NULL,
    device_pubkey   BLOB NOT NULL,
    credential_json BLOB NOT NULL,
    kt_leaf_index   INTEGER NOT NULL,
    kt_appended_at  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;

-- Peers whose identity key this profile verified against the KT log (INV-4):
-- the leaf coordinates it verified and the tree size the inclusion proof was
-- checked against. A peer row is the durable form of "attested".
CREATE TABLE citadel_peers (
    account_id         BLOB PRIMARY KEY NOT NULL,
    handle             TEXT NOT NULL,
    identity_pubkey    BLOB NOT NULL,
    kt_leaf_index      INTEGER NOT NULL,
    kt_appended_at     INTEGER NOT NULL,
    attested_tree_size INTEGER NOT NULL,
    attested_at        INTEGER NOT NULL
) STRICT;

-- A pending Welcome must be submitted with its recipient device ids
-- (SubmitMessageRequest::validate). JSON array of device id strings; NULL for
-- every other kind.
ALTER TABLE citadel_pending_transmissions ADD COLUMN recipient_device_ids TEXT;
