# 015: PR #69 local encrypted client store — K3 blocking review

- **Reporter:** k3 (blocking reviewer for the store under AGENTS.md's review structure)
- **Date:** 2026-07-28
- **Blocks:** PR #69 merge; M2 close
- **Related:** ADR-0007 (+ Amendment 1 ACCEPTED, Amendment 2 PROPOSED),
  `docs/issues/009` (design review), `docs/issues/012` (build findings),
  `docs/issues/013`, `docs/issues/014`

Reviewed at `b772c0f` (PR tip). The code is identical to `b2906ad`; the three
later commits are docs and CI only. Every finding below was verified against
source in the reviewer's own worktree; citation-level claims from the six
parallel verification passes were spot-checked personally before being used.
Test execution evidence is CI's (run 30329679255, all jobs green): this
reviewer's Windows host cannot build the vendored-OpenSSL graph (MSYS perl
lacks `Locale::Maketext::Simple`), which is recorded here rather than
papered over.

## Verdict

**CHANGES.** The implementation is faithful to the accepted design in the
large — key handling, the hardened open sequence, the startup state machine,
the ledger, the actor's transaction discipline, and all three credential
adapters verified clean — and the CI evidence is real, including the
native-backend conformance job that now passes against a live Secret Service.
Three items must be resolved before merge. None is a redesign; all three are
accountability gaps between the accepted evidence contract and what the PR
delivers, which is the exact defect class this project keeps catching.

This review also answers `docs/issues/012`: the three confirmed defects are
handled correctly in code, and **I concur with DEFECT 4's overturn of my own
§D.2 verification**. My Amendment 1 re-review verified that the
`max_past_epochs = 0` pin was right and that drift must fail closed; it did
not verify that the check was writable against the public API, because I read
the `max_past_epochs()` getter at `config.rs:191` without noticing it belongs
to `MlsGroupCreateConfig` (impl opens at `:174`), not to the
`MlsGroupJoinConfig` that `MlsGroup::configuration()` returns. The premise
was wrong; the conclusion stands; the serde-representation check the build
shipped (`crypto.rs:75-81`) reads what is actually on disk and is arguably
the stronger mechanism. Amendment 2 §A records this correctly.

## Required before merge

### R1. Amendment 2 §D's normative comment requirement is unmet

Amendment 2 §D closes with: "Its source comment must use the wire-message
rationale above rather than the withdrawn 'caller cannot know' premise."
`store/actor.rs:657-659` says, verbatim, the withdrawn premise:

```rust
// The kind is fingerprinted as ReceiveApplication for both cases: the
// caller cannot know which it is before decrypting, so using two
// kinds would make a retry look like an OperationIdConflict.
```

`content_type` is cleartext in `PrivateMessage` (RFC 9420 §6.3.2; 012's
DEFECT 3 withdrawal). The *mechanism* is right — one fingerprint over group
id plus complete wire bytes, parsed once inside the transaction — and §D's
two real justifications (fingerprint identity is content-type-independent;
a caller-side parse followed by an actor-side parse can disagree) are the
ones the comment must carry. This is a one-comment fix, and it is blocking
anyway: the PR asks charge to accept an amendment whose one explicit,
checkable requirement the code then violates on merge day. A blocking review
that waves its own amendment's normative sentence through is not a gate.

### R2. `store_whole_file_rollback_boundary_is_explicit` — absent, and its absence is recorded nowhere

ADR-0007's Evidence section names this test, and Amendment 1 §A.7 states that
no evidence test is renamed, removed, or weakened. The test does not exist —
the name appears nowhere in `crates/`, `.github/`, or `docs/` outside the ADR
itself — and `store/tests.rs:1-21`'s absence list, which is candid about four
other missing tests, does not mention it. A named test that silently vanishes
is worse than a deferred one, because the header's own convention ("Names
match the ADR's Evidence list so a reader can diff this file against it")
then actively misleads the diffing reader.

The property it pins matters: §6 states plainly that whole-file replacement
with a valid older snapshot also rolls back the database-resident KT
checkpoint and that M2 does not detect it. The test is what keeps every API
and document honest about that boundary. It is also cheap to write: restore
an older encrypted snapshot set, open it through the production hardened
path, show the KT checkpoint reads back rolled back, and assert nothing in
the API reports page authentication as freshness. Either implement it, or add
it to the recorded deferral list with charge's explicit sign-off. Silently
absent is the one option that is not available.

### R3. The codec's committed golden corpus does not exist, and the v2-migration half is unimplemented

ADR-0007 §1: "A committed schema-complete golden corpus pins the bytes that
v1 writes and proves they round-trip after restart." The Evidence entry
requires byte-comparing that committed corpus and migrating to a test v2
codec in one transaction. What `store_codec_v1_roundtrips_golden_corpus_and_migrates`
(tests.rs:737) actually does is generate its data **live** each run and prove
decode→re-encode byte-equality within one build. There is no committed corpus
(anything matching `corpus*` exists only as a live `Vec` in the test), no
migration to a test v2 codec (v2 appears only as an unknown identifier to
reject), and schema-completeness is asserted as a floor (`rows.len() >= 5`),
not as an enumeration.

The within-build round-trip proves the codec is deterministic today. It does
not prove that bytes written by v1 yesterday still decode identically
tomorrow — which is the entire reason a pinned, identifier-bound storage
codec exists, and the exact drift that would silently corrupt user stores at
upgrade time with every individual check green. Required: commit a corpus
(bytes plus a manifest enumerating every storage entity the code writes),
byte-compare it in the test, and either implement the single-transaction v2
migration case or record its narrowing. The codec *mechanism* itself is
sound — BTreeMap ordering, compact writer, trailing-input rejection, all
unit-pinned in `codec.rs` — so this is evidence completion, not redesign.

## Non-blocking findings (record; each names its follow-up)

- **N1 — `reconcile()` narrows §5's enumerated reconciliation and conflates
  two distinct outcomes.** §5 says the actor "reconciles the durable group
  epoch, operation receipt, idempotency key, and stored wire bytes";
  `actor.rs:1146-1166` reads only the operation receipt. The shared-atomic-unit
  argument makes the receipt logically sufficient, so this is a spec-text
  narrowing, not a soundness hole. The same function maps
  `LedgerCheck::Fresh` — a *proven*-not-applied outcome, since receipt and
  mutation share one atomic unit — to `StoreOutcomeIndeterminate`, which §5
  reserves for "recovery cannot read or validate the receipt." The chosen
  direction is conservative (a caller that could safely retry is told to
  reconcile instead), but it discards information the receipt check just
  established. Also note: this entire path is **untested** — no test injects
  a commit error, so the indeterminate machinery has never executed anywhere.
  Follow-up: either narrow §5's wording (Amendment) or distinguish
  proven-not-applied in the outcome type; add the commit-error injection test
  either way.
- **N2 — `accept_kt_head` persists an unverified `(tree_size, root_hash)`.**
  §5's atomic unit is "accept KT advancement: *verified* signed tree head
  plus the monotonic anti-rollback checkpoint." The API takes no signed head
  and no consistency proof; the monotonic check (reject shorter; reject
  equal-size different-hash) is real, but a *larger* forked head is accepted
  unchecked because an RFC 9162 consistency proof is not an input (ADR-0001's
  anti-rollback rule requires one). Verification currently lives entirely
  with the caller (there are no production callers yet), so nothing unsafe
  happens today — but the doc comment "Accept a signed KT tree head"
  overstates what the function receives, and the shipped API invites a future
  caller to advance the checkpoint on unverified data. Follow-up before M3
  wires KT advancement: rename/re-document the operation as recording an
  already-verified head and state where consistency verification lives, or
  take the signed head and proof as inputs.
- **N3 — evidence-depth gaps inside tests that exist.** Each is a named
  sub-element of an ADR test that the current test does not exercise:
  no `i64::MAX` sequence-exhaustion test (`OperationSequenceExhausted` has
  never fired anywhere); the "rolls back both schemas" injection in
  `store_provider_and_application_share_one_transaction` fails at lookup
  *before* any mutation, so it cannot distinguish rollback from never-started;
  `store_receive_is_atomic_with_plaintext_and_mls_state` injects failures
  before commit only, not during it; `post_restart_snapshot_proves_mls_forward_secrecy`
  checks snapshot eligibility but never injects the process stops on both
  sides of the commit point or recovers an indeterminate outcome; the
  first-create test has no two-process race, no symlink/reparse substitution
  case (only a directory decoy), and no per-step process stops; the
  migrations test has no injected-failure rollback case; the clean-open test
  infers rather than instruments the absence of `cipher_integrity_check`.
  None of these vacates the properties the tests do prove; all of them are
  gaps between the ADR's named elements and the evidence. charge should rule
  on which sub-elements are required for M2 and which are recorded
  strengthenings.
- **N4 — `store_release_excludes_secret_evidence_paths` is absent and
  unrecorded**, and there is no release-graph guard for the `testing`
  feature. The gate is currently convention only: `testing = []` is inert and
  only `test-harness` enables it, but Cargo feature unification means a
  future production binary in the root workspace built in the same invocation
  as `test-harness` would compile `citadel-core` with `store::evidence` and
  `database_encryption_key_for_evidence` included. The PCS extractor this
  test was written to exclude does not exist yet, so there is nothing secret
  to leak today. Follow-up: a cheap `cargo tree`-based CI assertion on the
  production feature graph, plus adding the named test to the deferral list.
- **N5 — `store_epoch_transition_removes_obsolete_secret_bytes`: the logical
  half is strong, the load-bearing half is deferred.** The test captures the
  exact pre-transition `message_secrets` rows, fails itself if the
  pre-transition recovery control misses a value, and proves the values are
  gone from provider rows and from raw file bytes afterward. The
  `SQLITE_ENABLE_DBPAGE_VTAB` + `dbdata.c` page-reconstruction half — the
  half that would prove unrecoverability from freed pages — is not built, and
  the test header says so plainly. Additionally, nothing ensures a captured
  value spans an overflow chain (">1 page"), so even the logical half misses
  a named element. Recorded as PARTIAL in `docs/status/core.md`, which is the
  right posture.
- **N6 — small items, one line each.** Dead duplicate
  `StoreError::PastEpochRetentionRejected` (only the `GroupError` variant is
  constructed); CSPRNG/hash failures in `ledger.rs` map to
  `StoreError::Migration`, a misleading variant; `receive`'s commit branch
  stores the MLS epoch in `citadel_delivery_cursors.last_sequence`, two
  monotonic counters under one name; a partial-NULL outcome row maps to
  `OperationReceiptExpired`, masking on-disk corruption as routine expiry;
  `welcome_key` derives the Welcome idempotency key by XORing one bit of the
  operation id — works for CSPRNG ids, a domain-separated hash would be
  idiomatic; the Unix install rename is not fail-if-exists at the syscall
  (Windows's `MoveFileExW` is; the held profile lock mitigates);
  `pending.proposed_epoch.unwrap_or_default()` silently defaults an MLS epoch
  to 0 on a path that is unreachable today.

## What held under review

- **Key handling (§2).** 32 bytes from the provider's OS CSPRNG, never
  derived, encoded in exactly one place as the canonical `x'<64 lowercase
  hex>'` raw-key literal built inside a `Zeroizing` owner; redacted `Debug`;
  no `Serialize`; no application KDF.
- **Hardened open (§3 as amended).** Exact A.6 sequence:
  `cipher_memory_security` before `PRAGMA key` (Amendment 2 §E), TEXT
  readback parsed strictly, `cipher_version` = `4.5.7 community`,
  `cipher_provider` = `openssl`, encrypted-schema-access codec proof, every
  §3 setting set *and* read back, DEFENSIVE and TRUSTED_SCHEMA checked at
  db-config level too, and the behavioral `load_extension` probe that
  requires exactly `not authorized` — distinguishing "refused" from "reached
  the loader," which is what makes it evidence. Plaintext SQLite header
  rejected before state classification.
- **Startup state machine (§2).** All seven table rows conform, including
  the lock-before-inspection ordering, read-back-after-write of the
  credential entry, `StoreKeyMissing`/`StoreStateInconsistent` with no
  replacement and no reset anywhere, and Unix `rename` + parent-directory
  sync. The Windows install is a **direct `MoveFileExW` with
  `MOVEFILE_WRITE_THROUGH`** (`lifecycle.rs:305-327`), not `std::fs::rename`
  — the one divergence I expected to find and did not.
- **Destruction (§6).** Actor closed first, all three credential deletions
  attempted with structured partial-failure reporting, closed-enumeration
  file removal, lock released last, confirmed-absent semantics.
- **Ledger (§5).** Exact `citadel-operation-request-v1` domain prefix, the
  same two-step deterministic JSON as the codec, SHA-256 through the existing
  RustCrypto primitive, conflict/expired/exhausted semantics all fail closed
  without mutation, the 256-outcome ring prunes payloads only and never
  ledger rows, and the high-water sequence is checked and monotonic.
- **Actor (§5, Amendment 2 §B).** One dedicated thread, one connection,
  `TransactionBehavior::Immediate` everywhere, groups loaded fresh per
  operation, the ledger governing exactly the nine named methods with the two
  named exceptions correctly unledgered, no network inside any transaction,
  and — critically — no blind repeat of an MLS mutation after an
  indeterminate commit.
- **Credential adapters (§2).** Windows: direct `CredReadW`/`CredWriteW`/
  `CredDeleteW` through `windows-sys` 0.61.2 with `CRED_PERSIST_LOCAL_MACHINE`,
  and the RAII owner zeroizes the blob **before** `CredFree` on every exit
  path including malformed lengths — audited line by line. macOS: the
  concrete Apple-native builder; non-synchronization is structural (legacy
  `SecKeychain*` API, verified against the pinned keyring 3.6.3 source), not
  assumed. Linux: the concrete Secret Service builder with `crypto-rust`
  mandatory, and its Diffie-Hellman enforcement is now exercised in CI (see
  below). The double exists only under `cfg(test)`/`testing` and can inject
  the full error taxonomy. Unsupported targets are a compile error.
- **Amendment 2 §A.** `retained_past_epochs` reads the persisted
  representation of the join configuration; non-zero fails as
  `PastEpochRetentionRejected`, unextractable as
  `PastEpochRetentionUnreadable`, and nothing defaults an unreadable value to
  zero. The test rewrites the persisted row to 3 and proves the load refuses.
- **Build surface.** `deny.toml` narrowing is exactly Amendment 1 §B.2's
  shape with `native-tls` still banned; `openssl-sys` appears in the lock
  only under `libsqlite3-sys`; one `rusqlite`, one `libsqlite3-sys`;
  `serde_json` `preserve_order` is off workspace-wide (verified with
  `cargo tree`); the crypto-confinement checker passes; the CI delta is
  purely additive and weakens no existing gate.
- **The forward-secrecy test** asserts the full
  `ValidationError → UnableToDecrypt → SecretTreeError(TooDistantInThePast)`
  chain, the pre-transition positive control, the post-transition
  current-epoch control, and an anti-overclaim assertion that retained
  plaintext history in the same snapshot remains readable — the §6 boundary,
  in code.
- **CI evidence.** Run 30329679255 is green across every job, including
  `store · native Secret Service backend`: the provisioning gate resolved the
  default collection (`/org/freedesktop/secrets/collection/login`) and both
  live-backend tests passed against real gnome-keyring. Native credential
  backend conformance is therefore **one of three platforms** (Linux), up
  from zero when this PR opened. Windows and macOS remain unprovisioned, and
  Amendment 2 §G's zero-of-three record was accurate at writing.

## Decisions required from charge

1. **Accept or reject Amendment 2.** The code implements it; the unamended
   §6 accessor premise is unimplementable (012 DEFECT 4). If charge rejects
   it, the implementation divergences the amendment records become open
   items instead. This review recommends acceptance: §A is a stronger check
   than the original design, §B/C/E/F/G are honest narrowings, and §D is
   correct once R1 lands.
2. **R2 and R3** if the core lane prefers recorded deferral over
   implementation: that is charge's call, not the lane's and not mine.
3. **PR #73 (the store-evidence provisioning fix) is superseded** — its
   content landed in #69 as `b772c0f`, and the branch it targets will
   disappear on #69's merge. It can be closed unmerged; authorship is
   preserved by branch prefix either way.

## Scope boundaries

This review does not re-run the test suite locally (host toolchain recorded
above), does not review the Windows or macOS adapters by execution (no
runners exist — source review against pinned upstream crates only), does not
weaken any named evidence test, and does not count M2: the milestone stands
at three of five criteria, with the FS harness test
(`device_compromise_past_messages_unreadable_fs`) and the PCS differential
oracle both still unwritten — see `docs/issues/014` and its answer.
