# 014: M2 exit acceptance-harness review

- **Reporter:** security review
- **Date:** 2026-07-27
- **Blocks:** M2 close
- **Related:** commit `295d829`, ADR-0005 Evidence, ADR-0007 §6,
  `docs/issues/010-pcs-oracle-feasibility.md`

## Verdict

**CHANGES.** Three of five M2 exit criteria are green. Four harness tests are
useful evidence for the behavior they actually run, but
`pcs_recover_after_update` proves functional
self-update recovery and post-update interoperability, not post-compromise
security. The status and milestone accounting must not call PCS green.

## Blocking finding

### `pcs_recover_after_update` has no compromised-state or decryption oracle

ADR-0005 defines this test as capturing compromised pre-update state and
proving that state cannot decrypt a never-processed post-update ciphertext
(`docs/decisions/0005-m2-dm-delivery-wire-model.md:353`). ADR-0007 strengthens
the evidence contract: `post_restart_update_proves_post_compromise_security`
must persist and restart, extract the relevant pre-update private state, parse
the UpdatePath, and attempt every applicable ciphertext through the pinned
`mls-spec`/AWS-LC differential oracle
(`docs/decisions/0007-local-encrypted-client-store.md:782-789`).
`docs/issues/010` records a preliminary throwaway API/dependency probe and
selects the full oracle as the intended rung. The probe was deleted and is not
committed evidence. The accepted ADR still requires the full implementation
and says PCS evidence and M2 close are blocked without it.

The merged test (`crates/test-harness/tests/m2_dm.rs:395`) does none of those
things. It sends a baseline, performs a self-update, merges the commit on all
members, and proves current members can exchange messages at the new epoch.
That is a valuable recovery/convergence test, but a compromised pre-update
state is never captured and never attempts the new ciphertext. The test can
pass even if the old state retains every key needed by the attacker.

**Required fix:** keep this test under a recovery/convergence name, remove PCS
claims from status and milestone counts, and implement the accepted
`post_restart_update_proves_post_compromise_security` oracle before calling PCS
green. Do not replace it with an OpenMLS-only negative assertion.

## Non-blocking finding

### F2 claims identical membership but asserts only count and epoch

The module documentation says all clients converge on identical membership
(`crates/test-harness/tests/m2_dm.rs:7`), while the assertions check only
`member_count() == 3` and epoch equality (`:186-201`). Three different
three-member trees at one epoch would satisfy those assertions.

**One-line fix:** expose a deterministic member-identity or tree-membership
view from `citadel-core` and compare the complete expected membership on every
client, or narrow the claim to count and epoch.

## Evidence that held

- `f4_send_receive_roundtrip` drives the real REST, WebSocket, sync, OpenMLS,
  and padding paths in both directions.
- `no_plaintext_scan_delivery_tables` is non-vacuous: recipients decrypt the
  canaries, delivery rows exist, and the scanner checks the live database.
- `adversarial_ds_swapped_keypackage_rejected` uses a live rewriting proxy,
  a valid honest control, a victim-account credential with attacker keys, and
  verifies rejection before group state is created.
- `LiveKtVerifier` performs asynchronous live-log verification first and
  exposes only verified facts to the synchronous OpenMLS callback.
- The deliberate omission of
  `device_compromise_past_messages_unreadable_fs` was honest at `295d829`.
  The persisted-state API now exists, so the omission must be closed by K3
  rather than relabeled.

## Persisted-state handoff to K3

`crates/test-harness` already enables `citadel-core`'s `testing` feature. That
feature exposes `citadel_core::store::evidence`:

- `CapturedSnapshot::capture(&LocalStore, path)` copies the database and every
  present SQLite sidecar and carries the correct database encryption key;
- `CapturedSnapshot::reopen()` opens the copy through the production hardened
  SQLCipher/provider path;
- `ReopenedSnapshot::{group_epoch,max_past_epochs,try_process_message}` expose
  the persisted epoch, the persisted zero-retention pin, and the real OpenMLS
  receive result while rolling back each probe; and
- `LocalStore::{paths,close}` support an explicitly quiescent file capture
  when the test needs to copy after shutdown.

Obsolete state is deleted by the same operation the test must drive.
`LocalStore::receive` merges an incoming commit, or
`prepare_self_update` plus `confirm_self_update` merges a local commit, inside
the store transaction. OpenMLS 0.8.1's merge path writes the new
`MessageSecretsStore`; with `max_past_epochs = 0`, its `add` method retains no
past secret tree. The same merge calls
`delete_previous_epoch_keypairs`, which invokes the storage provider's
`delete_encryption_epoch_key_pairs` for the preceding epoch. Because
`StoreProvider` borrows that transaction, those provider deletions and
Citadel's epoch update commit atomically.

The final FS test should follow the accepted boundary exactly: prove a
pre-transition persisted snapshot can decrypt an unseen old-epoch application
ciphertext; merge and persist the transition; capture current files plus the
correct key without vacuum or test-only cleanup; prove a current-epoch positive
control; then require the old ciphertext to fail with OpenMLS's exact
`TooDistantInThePast` chain. Retained plaintext history is outside the claim.

## Harness provider gap and ownership

The persisted-state API is necessary but not sufficient. `DmClient` owns an
`EphemeralProvider`, and its KeyPackage, group, send, and receive methods call
`DmGroup` directly. Every current M2 harness scenario therefore loses MLS state
at process exit. Calling `CapturedSnapshot` from one test cannot repair that
architecture because there is no `LocalStore` state to capture.

K3 owns the harness integration. `crates/test-harness` is K3's surface, so K3
must add a durable client mode that drives `LocalStore` operations for the live
F2/F4 transport path, supplies fresh `OperationId` values, translates
`OperationOutcome` without duplicating MLS logic, and supports close, reopen,
and snapshot capture. The adapter must drive `LocalStore`; it must not expose
or retain `StoreProvider`, whose transaction borrow is deliberately internal.
The existing three green criteria remain evidence for their stated functional
claims. The remaining FS and PCS criteria must use the durable mode.

The durable mode must transmit from `LocalStore::pending_transmissions`, using
each row's persisted wire bytes and 16-byte idempotency key. Completion depends
on how the row was created. Ordinary application messages, Welcomes, and
already-merged membership commits call `acknowledge_transmission` only after
terminal transport acceptance. A prepared self-update commit must remain
pending until that transmission's outcome is accepted or rejected; acceptance
calls `confirm_self_update`, rejection calls `abort_self_update`, and an
indeterminate result calls neither. Both self-update methods remove the pending
row in the same transaction as the MLS transition. The current
`PendingTransmission` fields do not distinguish a prepared self-update from an
already-merged commit: both can have `kind == "commit"` and a non-null
`proposed_epoch`. Core therefore owns a required typed completion-disposition
field or equivalent query before K3 wires the outbox. K3 must not infer it from
the current fields.

The current `DmClient::submit` generates a new UUID for each call. Reusing that
path would persist MLS state while bypassing the store's crash-safe outbox
contract. The acceptance client should be explicitly durable rather than
selectable between ephemeral and durable providers, so a later default cannot
silently move these criteria back to memory.

Core owns the persisted and cryptographic evidence primitives. That includes
`LocalStore`, the `testing`-gated credential double and profile paths,
`CapturedSnapshot`/`ReopenedSnapshot`, the exact OpenMLS failure oracle, and any
additional typed surface the durable harness cannot obtain without reaching
into store internals. K3 should file a concrete missing-surface request rather
than reimplementing store or OpenMLS behavior in the harness.

One missing Core surface is already visible: the durable path needs a typed
membership view so F2 can compare exact member identities, not only epoch and
member count, without reading provider tables. Core owns that addition. The
forged attacker KeyPackage fixture may remain ephemeral because it is hostile
input, not honest client state.

The PCS split follows the same boundary. Core owns implementation of ADR-0007
§6's captured-state differential proof, including the pinned independent
oracle and the control-versus-capture result. K3 owns the harness-level exit
test that runs the live update through the durable client mode and invokes
that Core-owned proof. Neither the existing store unit test nor a new
Core-only PCS unit test satisfies PLAN §9 by itself.

## Decision required from charge

No new decision is needed for the FS test. M2 close must, however, be counted
from the accepted PCS evidence contract rather than from the current test name.

## Scope boundaries

This review does not implement K3's durable harness mode or FS test, weaken the
PCS oracle, or treat functional recovery as a secrecy proof.
