# Core lane status: the M2 store is built; FS and PCS evidence remain

**Lane:** security core. **Branch prefix:** `core/<task>` (`sol/` and `opus/` are retired;
they survive in merged history only — do not cut new branches under either).
**Audience:** a fresh instance of this lane with **zero memory of this build**. Read
`plans/PLAN.md`, `plans/AGENTS.md`, `plans/PLAN-CORE.md`, then this file, then
`docs/status/advisor.md` for the live queue, which is authoritative on ordering.

**This file is named for the lane, not the model, deliberately.** The seat has changed hands
four times in eleven days, twice to and from the same model as usage quota came and went. The
authoritative record of who holds it is the roster table in `plans/AGENTS.md`, which logs every
swap under rule 12. Do not rename this file, and do not put a model name in its title — the
roster table is the only place one belongs.

---

## Start here: what happened, in five lines

ADR-0007 (local encrypted client store) was designed, independently reviewed by K3, amended
once, and ACCEPTED by charge on 2026-07-26 (`d302e76`). The store was then built against the
accepted design, with the build-time divergences now proposed as Amendment 2, and is **PR #69**
on branch `core/local-encrypted-store`. It is out of draft. K3's blocking review in PR #74
returned **CHANGES** with three required items; the complete shutdown queue is at the end of
this file. Four defects found in the ADR during the build are filed as
`docs/issues/012`; three hold, one is withdrawn with its reasoning kept. The persisted-state
FS test belongs to K3. The accepted differential PCS oracle is also still unbuilt; issue 014
corrects the prior milestone count. **M2 is three of five, not four of five.**

charge subsequently assigned Amendment 2 explicitly. The proposed text is now in ADR-0007;
it has no force until charge accepts it after K3's blocking review.

---

## What is BUILT

`crates/citadel-core/src/store/`, ~everything ADR-0007 §1-§6 specifies that does not require
release CI. MLS state is no longer held in memory: the old `crypto::Provider` alias is gone,
replaced by an explicitly named `crypto::EphemeralProvider` for the cases that still have no
store, and `store::StoreProvider` over a keyed SQLCipher connection for everything else.

**Module map:**

| Module | What it owns |
|---|---|
| `key` | The 32-byte database encryption key and its canonical raw SQLCipher literal. No `Display`, no `Serialize`, redacting `Debug`. |
| `credentials` | The OS credential-store contract, with Windows, macOS and Linux adapters and a `cfg`-gated test double. Windows calls `CredReadW`/`CredWriteW`/`CredDeleteW` directly because keyring 3.6.3 hard-codes `CRED_PERSIST_ENTERPRISE`. |
| `paths`, `lock` | Fixed profile paths, containment checks, the `File::try_lock` exclusive profile lock. |
| `open` | Keying, the §3 hardening set with readback, Amendment 1 §A.6's codec sequence, the N1 extension probe. |
| `schema`, `migrations/` | Application schema with its own named migration history, separate from the provider's. |
| `codec` | `citadel-openmls-json-v1`: deterministic, rejects trailing input. |
| `provider` | `RustCrypto` + `openmls_sqlite_storage` over a **borrowed** connection. |
| `ledger` | Operation IDs, request fingerprints, the monotonic sequence, the 256-outcome ring. |
| `lifecycle` | §2's seven-row startup state machine, staged creation, destruction. |
| `actor` | The public `LocalStore`: one connection, one thread, one transaction per operation. |
| `evidence` | `testing`-gated snapshot capture and reopen, for the §6 evidence. |

**The persisted-state API**, stated explicitly because it is what K3's remaining test drives:

- `LocalStore::open(ProfilePaths, Arc<dyn CredentialStore>)`, plus `close()` and `destroy()`.
  `ProfilePaths::at_root` is `testing`-gated so a test can put a profile in a tempdir;
  production has no way to relocate one out of the platform application-data directory.
- Profile lifecycle follows the startup, close, and destruction contracts in ADR-0007 §§2
  and 6, not the operation ledger.
- Ledgered state-changing calls take a caller-generated `OperationId` and return an
  `OperationOutcome`: `create_group`, `join_from_welcome`, `add_members`, `send`, `receive`,
  `prepare_self_update`, `confirm_self_update`, `abort_self_update`, and `accept_kt_head`.
  Retrying the same ID with the same fingerprint returns the stored outcome without
  reapplying.
- Two state-changing calls are transactional but unledgered:
  `new_key_package`, whose crash-recovery limitation is proposed in Amendment 2 §B.1, and
  `acknowledge_transmission`, a naturally idempotent delete keyed by the pending
  transmission's existing 16-byte idempotency key (§B.2).
- Reads: `conversations`, `messages`, `pending_transmissions`, `kt_checkpoint`,
  `group_epoch`, `operation_high_water`, and `verify_integrity`.
- Evidence surface (`testing` feature): `LocalStore::paths()` enumerates every file the profile
  owns; `database_encryption_key_for_evidence()` returns the correct key;
  `evidence::CapturedSnapshot::capture_files(&paths, key, into)` copies the live set with **no**
  cleanup step; `has_live_rollback_journal()` reports snapshot eligibility; `reopen()` keys the
  copy through the production open sequence; `ReopenedSnapshot::try_process_message` drives the
  real OpenMLS path **bypassing application deduplication**, handing back OpenMLS's own typed
  error, which is what makes an exact-chain assertion possible. A persisted field that cannot
  be extracted is rejected during `DmGroup::load` as
  `StoreError::Group(GroupError::PastEpochRetentionUnreadable)`. A nonzero value is rejected as
  `StoreError::Group(GroupError::PastEpochRetentionRejected(value))`. The evidence accessor
  returns `Option<usize>` only after a valid group has loaded; it cannot expose either rejected
  case as `Ok(None)`.

**How obsolete epoch state is deleted**, since that is the other half of what the test drives:
Citadel does not delete it. OpenMLS does, through its storage trait, in the same transaction
that persists the new state, because `max_past_epochs` is pinned to 0. The sequence is
`prepare_self_update` then `confirm_self_update` returning success, which on a live filesystem
has already removed the rollback journal, and only then is a snapshot eligible. There is no
checkpoint call, no vacuum, and no test-only cleanup, deliberately.

**Named tests that prove compliance**, all in `crates/citadel-core/src/store/tests.rs` against
**real SQLCipher and the real OpenMLS provider**:

- `store_first_create_is_atomic_and_credential_store_failures_fail_closed`
- `store_release_uses_only_pinned_sqlcipher`
- `store_provider_and_application_share_one_transaction`
- `the_outcome_ring_expires_payloads_without_ever_reapplying_the_operation`
- `store_codec_v1_roundtrips_golden_corpus_and_migrates`
- `store_rejects_plaintext_wrong_key_corruption_and_unverified_cipher`
- `store_disk_copy_without_key_contains_no_canary_plaintext` (with a non-vacuous scanner control)
- `store_receive_is_atomic_with_plaintext_and_mls_state`
- `store_restart_restores_group_and_pending_transmission_exactly_once`
- `store_restart_preserves_kt_anti_rollback_checkpoint`
- `store_migrations_are_encrypted_transactional_and_monotonic`
- `store_clean_open_does_not_run_a_full_integrity_scan`
- `store_profile_destruction_revokes_keys_and_reports_residual_files`
- `post_restart_snapshot_proves_mls_forward_secrecy`
- `a_group_whose_persisted_configuration_retains_past_epochs_fails_closed`

Also landed in the same PR, because rule 2 and Amendment 1 require it: the `deny.toml`
`wrappers = ["libsqlite3-sys"]` narrowing (a **named accepted consequence** per Amendment 1
§B.3, not a lint fix — read §B.3 and §B.4 before touching it), both `docs/issues/011` notes,
and this file.

---

## What is NOT built

Stated here and at the top of `store/tests.rs` rather than left to be discovered.

- **The three-desktop-target release build.** Never run. See the CI platform section below.
- **The per-OS native credential backend conformance run.** ADR-0007 §2 wants one runner per
  desktop target; only the Linux third exists (`store-evidence`).
- **The native manifest / SBOM / pinned-scanner job** of Amendment 1 §A.3.
- **The `mls-rs` / `mls-spec` / AWS-LC PCS differential oracle** (ADR-0007 §6).
  `docs/issues/010` records a preliminary throwaway API/dependency probe and the selected full
  rung, but the probe was deleted and is not reproducible committed evidence. Nobody has built
  the oracle. Its sharpest residual risk is that HPKE info/context label binding for UpdatePath
  open must match RFC 9420 and OpenMLS exactly.
- **The three-target latency benchmark.**
- **`device_compromise_past_messages_unreadable_fs`** — the fifth M2 exit criterion. **This is
  K3's, not this lane's.** Do not close it with a placeholder; a vacuous green test is worse
  than a missing one. K3 recorded the reasoning in `crates/test-harness/tests/m2_dm.rs`.

## What is PARTIAL

**`store_epoch_transition_removes_obsolete_secret_bytes`.** It exists and passes, and it is not
the test ADR-0007 specifies.

- **What it does prove:** the obsolete rows are gone logically, and the obsolete secret bytes do
  not appear verbatim in a raw scan of the database file.
- **What it does not do:** the `SQLITE_ENABLE_DBPAGE_VTAB` + `dbdata.c` page reconstruction the
  ADR calls for. Without that, a freed page still carrying old secret bytes in a region the raw
  verbatim scan does not reach would not be caught.
- **Why it matters:** this is a forward-secrecy claim, and FS is one of the properties this
  project exists to provide. The gap is narrow but it is on the security-critical axis.

The store-level FS proof that *is* complete is `post_restart_snapshot_proves_mls_forward_secrecy`:
the attacker gets the database, every SQLite sidecar, and the **correct** key. A pre-transition
control must decrypt the old-epoch ciphertext; after the transition the same never-processed
ciphertext must fail with the exact `ProcessMessageError::ValidationError` →
`UnableToDecrypt` → `SecretTreeError(TooDistantInThePast)` chain, while a never-seen
current-epoch message still decrypts. That is evidence the machinery works. It is not a
substitute for either the page-reconstruction test or K3's harness AC.

---

## Which platforms have NO CI job — read this before trusting a green check

**Every job in `.github/workflows/ci.yml` is `runs-on: ubuntu-latest`.** There is no Windows
runner and no macOS runner anywhere in this repository.

| Target | Compiled in CI? | Native backend exercised? |
|---|---|---|
| Linux | yes (`rust`, and `store-evidence` for the real Secret Service via `dbus-run-session` + gnome-keyring) | yes, Linux only |
| Windows | **no** | **no** |
| macOS | **no** | **no** |

What that means concretely, and it is more than "some tests don't run":

- **`store/credentials/windows.rs` is compiled by no CI job.** It is the adapter that calls
  `CredReadW`/`CredWriteW`/`CredDeleteW` directly. Nothing in CI type-checks it.
- **`store/credentials/apple.rs` is compiled by no CI job.** Same.
- **The Windows halves of `paths.rs` and `lock.rs` are compiled by no CI job** — including
  `FILE_FLAG_OPEN_REPARSE_POINT` and the `MoveFileExW` install path. Per `docs/issues/012`
  DEFECT 1, `SQLITE_OPEN_NOFOLLOW` is **inert on Windows**, so Windows path containment rests
  entirely on `ProfilePaths::validate` — code no CI job compiles, guarding a property the ADR
  claims cross-platform.

**The trap this actually sprang, so you do not repeat it.** This build was developed on Windows.
Local `cargo clippy -D warnings` was genuinely green — and it compiled `windows.rs` while never
compiling `secret_service.rs`. CI compiles `secret_service.rs` and never compiles `windows.rs`.
**Neither side ever sees both.** PR #69's first CI run failed on a one-line unused import in
`secret_service.rs` that no local gate could have caught. The same import was present in
`apple.rs`; it was fixed by inspection against the pinned keyring source, because no job will
ever tell you.

Until a Windows and a macOS runner exist, treat every `#[cfg(windows)]` and `#[cfg(target_os = "macos")]`
block in this crate as **unverified code**, regardless of how green the checks look.

**Related standing warning:** a green check is not evidence. Open the job log and confirm the
step actually ran. Every real defect this milestone was found by a human-style read of code or
logs, not by CI.

### RESOLVED: `store-evidence` failed first, then passed with real provisioning

The `store · native Secret Service backend` job was added by PR #69 and had never executed
before 2026-07-28. On its first real run it **failed**, and the failure is correct — it is
rule 4 working, not a broken test.

Run `30325276041`, job `90169795224`. Four tests run; two pass, two fail:

```
production_store_uses_the_one_fixed_service_identity  ... ok
secret_service_session_is_diffie_hellman_not_plain    ... ok
native_backend_roundtrips_and_deletes                 ... FAILED
the_three_items_do_not_alias_each_other               ... FAILED

panicked at store/credentials/secret_service.rs:195: write: Locked("Secret Service: no result found")
panicked at store/credentials/secret_service.rs:216: write dek: Locked("Secret Service: no result found")
```

The split is diagnostic. **The two that pass are the two that never talk to the daemon** — one
checks the fixed service identity, the other reads the resolved feature graph. **Both that fail
are the two that actually write to the live Secret Service.**

`Locked("Secret Service: no result found")` on a *write* is consistent with there being no
default collection to write into. `gnome-keyring-daemon --unlock --components=secrets` with
an empty password unlocks an existing login keyring, but the job does not inspect collection
state directly. The failed run supports an incomplete-provisioning diagnosis, but does not by
itself establish the exact cause.

**What this did and did not tell you.** It did **not** show the Linux adapter was wrong. The
adapter is reporting a genuine backend state, and `classify` mapped it to the right typed error.
It showed the job's provisioning step was incomplete.

K3 supplied PR #73, commit `5e83396`, which was applied unchanged as
`b772c0f`. The repair uses a non-empty throwaway keyring password and adds a
fail-fast `ReadAlias("default")` gate before tests. In
[run 30329679255](https://github.com/Phew/Citadel/actions/runs/30329679255),
the gate resolved `/org/freedesktop/secrets/collection/login`, then all four
credential tests passed. Both live Secret Service tests that failed in the
first run now pass, and the complete workflow finished successfully. Linux
therefore has real live native credential backend evidence. The job used the
default test profile and did not prove the production release graph excludes
the credential double and unsupported backends or that every returned secret
owner is zeroizing. The full ADR §Evidence release-conformance count remains
**zero of three platforms**.

---

## Open findings against ADR-0007 — `docs/issues/012`

Four defects were raised during the build, against an ADR that had already passed independent
review and been accepted. Read the file; the summary:

- **DEFECT 4 — CONFIRMED.** §6's fail-closed past-epoch check cannot be written against a
  public openmls 0.8.1 API. **This overturns part of K3's §D.2 verification.** The
  serde-representation read used instead is arguably the stronger check, since it reads what the
  provider actually persists.
- **DEFECT 2 — CONFIRMED, and it wants a decision.** §5's universal quantifier over
  state-changing operations conflicts with RFC 9420 single-use KeyPackages, and §5's atomic-unit
  list omits KeyPackage generation entirely. The unresolved case is an **orphaned private key**:
  a `new_key_package` whose transaction committed but whose caller never saw the response leaves
  private key material in the store that no protocol event will ever delete. Not fixed; the
  options are laid out in 012.
- **DEFECT 1 — CONFIRMED IN SUBSTANCE.** `SQLITE_OPEN_NOFOLLOW` is inert on Windows. See the CI
  platform section above. 012 also documents a citation hazard worth knowing: `libsqlite3-sys`
  0.30.1 ships **two** files named `sqlite3.c`, and this repo's convention is the `sqlcipher/`
  one. A review of this finding proposed a "correction" that was actually a citation from the
  other amalgamation; the disagreement and the evidence are both recorded in 012.
- **DEFECT 3 — WITHDRAWN, premise false.** `content_type` is a cleartext `PrivateMessage` field
  and is publicly reachable without decrypting. The single-`receive`-kind implementation may
  still be right, for reasons that have nothing to do with the withdrawn premise; 012 states them
  and leaves the call to the next occupant.

Plus two smaller findings carried in the same file: `cipher_memory_security` must be set
**before** `PRAGMA key` and returns TEXT not INTEGER (both load-bearing in `open.rs`); and §2's
"lock content is empty" holds only for a lock file this code created.

---

## What to do next, in order

1. **Get PR #69 through K3's blocking review.** It is out of draft. This lane does not
   self-merge and never self-reviews.
2. **Close the two inherited review findings.** The reviews are complete in issues 013 and
   014. Issue 013 requires an ADR-0005 lifecycle correction plus ordinary hardening. Issue 014
   blocks M2 close because recovery/convergence was mislabeled as PCS evidence.
3. **`docs/issues/012` DEFECT 2** needs a decision from charge before M3 — it interacts with the
   M1 KeyPackage pool and the M5 multi-device work.
4. **Integration checkpoint**, then charge declares M2. Being unblocked is not being in scope.

**Deferred by design. Do not start without explicit direction from charge:** M3 commit
ordering and F7 (the integration checkpoint gates it); the device-transparency `KtLeaf` proto
work (ADR-0004's named residual); ADR-0006 follow-ups A through D.

---

## Approved by K3's review and NOT to be reopened

These were verified and must survive intact — with the one correction 012 records against §D.2.

- The FS test's exact `ProcessMessageError::ValidationError` →
  `ValidationError::UnableToDecrypt` →
  `MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)` chain. K3
  reproduced it against openmls 0.8.1 source, and the `PublicMessage` path's `NoPastEpochData`
  divergence confirms the ADR is right to demand an application ciphertext.
- The `max_past_epochs = 0` pin with fail-closed behavior on OpenMLS default drift. **The pin
  and the fail-closed requirement stand; only the premise that it could be checked through a
  public accessor was wrong (012 DEFECT 4).**
- The PCS design's refusal to substitute a self-referential test, including that it blocks M2
  close rather than degrading the evidence.
- The shared-transaction type argument.
- The keyring `CRED_PERSIST_ENTERPRISE` justification (`windows.rs:246`, confirmed accurate).

## Standing corrections this lane must not re-litigate

- **There is no no-comments rule.** AGENTS.md rule 9 *encourages* comments at crypto call sites,
  invariant boundaries, and anywhere an auditor would ask "why," and explicitly replaces any
  prior no-comments rule. A previous holder of this seat filed comment removal as a blocking
  review finding; it was rejected. Verify a rule exists before enforcing it.
- **Rule 13:** no AI-attribution signatures in commits, PR bodies, code, or docs.
- The GitHub account is shared, so no agent can cast a formal PR approval. Post verdicts as
  labelled comments ("Core review — APPROVE" / "— CHANGES").

## Track record of this seat, for a fresh instance

The recurring failure mode here is **documentation that asserts things the code does not do.**
Instances so far: the `citadel-core` crate description claiming a local encrypted store that did
not exist; a test doc comment claiming swapped-KeyPackage coverage the test did not provide;
`plans/PLAN.md` M1 listing "citadel-core keychain integration" as delivered when it was never
built; Amendment 1 §A.5 asserting the open sequence checks extension loading is off without
naming a mechanism (fixed by the N1 behavioural probe); and `perf/README.md` documenting a
`--diff` behaviour the code did not have. Every one was caught by someone else reading the code.
**Treat prose about your own crate as a claim that has to be true.**

A second failure worth knowing: roughly a day of ADR-0007 design work sat uncommitted in a
sandbox worktree because the sandbox could not write the shared Git index, and the blocker was
raised at handoff instead of immediately. AGENTS.md rule 2 is not advisory. Commit early, and
escalate a tooling blocker the moment it appears.

## What previous holders delivered, for provenance

Through M1: citadel-proto contracts, the `citadel-service-crypto` facade, `kt-log` with a Go
RFC 6962 differential oracle, ADR-0004, ADR-0005, and the first citadel-core M2 engine. Day 5:
the `#47` respin that fixed both of K3's blocking findings and exceeded them (initiator-side KT
verification before any OpenMLS mutation, staged-commit processing with update-path
verification, typed deferral errors instead of silent drops), plus ADR-0007 and the catch that
PLAN.md's M1 keychain-integration claim was never true. 2026-07-26 to 2026-07-27: ADR-0007
Amendment 1, the store build (PR #69), and `docs/issues/011` and `012`.

## Repo facts a fresh instance will not infer

- Work in your own worktree. The primary checkout belongs to charge. Base every branch on
  `main`, never on another open branch. Open PRs early to get CI, and mark them **ready** when
  mergeable; a draft PR cannot be merged. Branches are deleted on merge.
- CI: `pull_request` is the canonical trigger; push runs only on `main`; docs-only diffs skip
  CI entirely (`paths-ignore` covers `docs/**`, `plans/**`, `**.md`). A docs-only PR therefore
  gets **no** checks — that is by design, not a broken pipeline.
- `db-tests` runs against real PostgreSQL 16 and structurally cannot catch runtime-image or
  packaging failures; those surface only in compose-smoke and the canary job.
- Two advisory suppression files are both load-bearing: `deny.toml` (cargo-deny) and
  `.cargo/audit.toml` (cargo-audit). **cargo-audit runs first and can fail the job before
  cargo-deny is ever reached.** Changing one without the other does not work.
- DB test isolation uses a throwaway per-test **database** (ADR-0006), not a per-test schema.
- **Building this crate locally on Windows** needs a Windows-native Perl for vendored OpenSSL;
  Git's msys Perl fails at `Configure` on a missing `Locale::Maketext::Simple`. A portable
  Strawberry Perl plus `OPENSSL_SRC_PERL` works. CI is Linux and needs none of that, but it does
  need `libdbus-1-dev`, which the compiling jobs install explicitly.

---

## 2026-07-27 verification, Amendment 2, and inherited reviews

PR #69 at `d370384` was verified independently; the handover note was not
treated as evidence.

### What the latest pull-request run actually executed

[GitHub Actions run 30325896448](https://github.com/Phew/Citadel/actions/runs/30325896448)
tested the merge of `d370384` into its then base. The logs, not the check badges,
show:

- Rust ran `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`, and
  `cargo test --workspace --locked`; all passed on Linux.
- The real compose job ran all five named M2 harness tests and they passed.
  This does not cure issue 014's PCS-oracle finding: a green test proves only
  the assertions it contains.
- The canary injected 16 values, scanned 13 tables, 27 rows, and 80 log lines,
  found both controls, and reported no service-data violations.
- `cargo audit`, `cargo deny check`, crypto confinement, and migration
  immutability checks passed. Audit reported only the two repository-allowed
  unmaintained advisories.
- The native Secret Service job ran exactly four credential tests. The two
  non-writing tests passed. Both live-write tests failed with
  `Locked("Secret Service: no result found")`. This is consistent with an
  absent default collection, but the job did not inspect collection state.
- Every job used `ubuntu-latest`. No Windows or macOS job exists.

K3's PR #73 was subsequently applied unchanged as `b772c0f`. The native job in
[run 30329679255](https://github.com/Phew/Citadel/actions/runs/30329679255)
resolved the default collection to the login collection and passed all four
credential tests. The complete run passed. Native credential backend
execution now has real Linux evidence; the full release-conformance contract
remains zero of three platforms.

### Local independent reproduction

The following commands returned success in a local Windows terminal with Rust
1.95.0 and about 49.6 GB free before the build:

- `cargo fmt --all -- --check` passed;
- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed;
- `cargo test --workspace --locked`, including the live Windows Credential
  Manager round-trip/delete cases;
- `cargo audit` and `cargo deny check` passed with the same two allowed
  unmaintained warnings;
- `cargo metadata --locked`, crypto confinement, and the migration checker
  against base `113b875` passed; and
- `git status` reported no changes after the build.

The terminal output was not committed or published, so this is an operator
report with exact rerun commands, not durable conformance evidence. It is not a
substitute for the committed three-platform release matrix.

### Amendment and review outputs

- ADR-0007 Amendment 2 is **PROPOSED**, not accepted. It covers all of issue
  012, corrects the additional acknowledgment-ledger exception, keeps one
  incoming MLS wire-message ledger domain on the correct rationale, and records
  the zero-platform CI state without weakening the requirement. The amendment
  specifies the correct wire-message rationale, but `actor.rs` still contains
  the withdrawn "caller cannot know" source comment; changing it is outside
  this doc-only batch.
- Two additional code-only cleanups remain outside this batch:
  `evidence.rs` still documents `max_past_epochs()` as if a loaded group could
  return `Ok(None)`, and the top-level
  `StoreError::PastEpochRetentionRejected` variant is unused. The enforced
  rejection path is through the nested `GroupError` variants documented above.
- `docs/issues/013-pr-39-delta-review.md` is the overdue review of `33fcfe9`.
  Its principal finding is that the safer Subscribe-based Welcome
  acknowledgment changed accepted ADR-0005 behavior without updating the ADR.
- `docs/issues/014-m2-exit-ac-review.md` is the review of `295d829`. The
  current `pcs_recover_after_update` test is a recovery/convergence test, not a
  PCS proof. ADR-0007's accepted differential oracle remains unbuilt, so M2
  cannot honestly be counted as four of five exit criteria green.

### Persisted-state handoff to K3

The exact test surface is
`citadel_core::store::evidence::{CapturedSnapshot, ReopenedSnapshot}`, compiled
through the `testing` feature that `crates/test-harness` already enables.
`CapturedSnapshot::capture` copies the encrypted database and present sidecars
with the correct key; `reopen`, `group_epoch`, `max_past_epochs`, and
`try_process_message` drive the production provider path against the copy.

Drive the transition through `LocalStore::receive` for a peer commit or
`prepare_self_update` plus `confirm_self_update` for a local commit. OpenMLS
writes a `MessageSecretsStore` that retains no past tree when
`max_past_epochs = 0` and calls `delete_previous_epoch_keypairs` for the prior
epoch. `StoreProvider` borrows the same transaction, so those deletions and the
Citadel epoch update commit together. Issue 014 gives the full test sequence
and exact accepted error oracle. This batch does not implement K3's test.

The handoff also has an integration boundary. Every current M2 harness client
stores MLS state in `EphemeralProvider` and calls `DmGroup` directly. K3 owns
the harness-side durable client mode because `crates/test-harness` is K3's
surface: it must drive `LocalStore` through the live transport flow, translate
typed operation outcomes, and support close, reopen, and snapshot capture
without exposing `StoreProvider` or duplicating MLS logic. The FS and PCS exit
criteria must run through that durable mode.

The durable mode must submit the store's persisted pending-transmission bytes
under their stored idempotency keys. Ordinary messages, Welcomes, and
already-merged commits are acknowledged only after terminal acceptance.
Prepared self-updates instead call `confirm_self_update` after acceptance,
`abort_self_update` after terminal rejection, and neither while the result is
indeterminate. The current `PendingTransmission` fields cannot distinguish a
prepared self-update from an already-merged commit, so Core owns a typed
completion-disposition addition and K3 must not infer the transition. Calling
the current `DmClient::submit`, which invents a new UUID, would bypass the
durable outbox contract. The acceptance client must be explicitly durable
rather than provider-selectable. The forged attacker package fixture may remain
ephemeral because it is hostile input, not honest client state.

Core owns the store and cryptographic proof surfaces. Core will supply the
typed pending-completion disposition above, any other missing typed `testing`
API that K3 identifies, and ADR-0007 §6's
captured-state differential PCS implementation, including its independent
oracle. The first already-visible addition is a typed durable membership view,
so F2 can compare exact member identities without reading provider tables. K3
owns the harness-level PCS criterion that invokes the Core-owned proof after
driving the live update. A Core-only unit test is necessary component evidence,
but it does not satisfy PLAN §9's harness criterion.

---

## Shutdown snapshot 2026-07-28

This section supersedes earlier queue and branch-state paragraphs where they
conflict. It is written for a reader with no session memory.

### Current evidence and milestone state

- `main` is `745cae1`. The tested store implementation/evidence head is
  `88e1152` on `core/local-encrypted-store`, PR #69, out of draft. The
  shutdown status commit follows it without changing code.
- GitHub Actions run
  [30331164102](https://github.com/Phew/Citadel/actions/runs/30331164102)
  tested `88e1152` and completed successfully. Seven jobs succeeded: the path
  filter, format/clippy/workspace tests, audit/deny plus confinement and
  migration checks, PostgreSQL 16 tests, compose and stack-backed harness
  tests, the no-plaintext canary, and the live Linux Secret Service job. The
  desktop job was skipped by its path filter.
- The native job resolved the default collection to
  `/org/freedesktop/secrets/collection/login` and all four credential tests
  passed. This is real Linux live credential backend execution. It is not the
  ADR's named release-CI conformance evidence: there is no release-profile
  graph check, Windows runner, or macOS runner. Full release conformance
  remains unimplemented on all three platforms.
- The compose log ran all five current M2 harness tests. Its
  `pcs_recover_after_update` success does not prove PCS. M2 remains **three of
  five**: persisted-state FS and the captured-state differential PCS criterion
  are both open.
- K3's blocking review is PR #74 and returned **CHANGES**. PR #69 must not
  merge until R1 through R3 below are resolved and K3 re-reviews them.

### What did not run or does not exist

- The desktop job in run 30331164102 was skipped by the path filter.
- No CI job runs on Windows or macOS. No job builds the store's production
  release feature graph on any platform.
- `device_compromise_past_messages_unreadable_fs` and
  `post_restart_update_proves_post_compromise_security` do not exist.
  `pcs_recover_after_update` ran, but its success-only assertions are not the
  differential PCS criterion.
- `store_whole_file_rollback_boundary_is_explicit` does not exist.
- `store_codec_v1_roundtrips_golden_corpus_and_migrates` ran, but the named
  committed corpus and transactional test-v2 migration do not exist. The test
  proves only current-build determinism and round-trip behavior.
- `store_release_excludes_secret_evidence_paths`, the three-platform release
  graph checks, and the all-desktop-target hot-path benchmark do not exist.
- The freed-page reconstruction half of
  `store_epoch_transition_removes_obsolete_secret_bytes` remains deferred; the
  existing test proves logical provider-row and raw-file-byte deletion only.
- Local Windows verification ran format, clippy, workspace tests, audit, deny,
  locked metadata, crypto confinement, and the migration checker. Local
  PostgreSQL and compose tests remained ignored; run 30331164102 executed those
  tests against PostgreSQL 16 and the real Compose stack instead.

### Claim audit for this session

- The M2 correction holds after re-reading every accepted criterion: F2, F4,
  and the no-plaintext criterion have evidence; persisted-state FS is absent;
  the current recovery test does not satisfy PCS.
- The overdue PR #39 and M2 harness reviews in issues 013 and 014 remain
  supported. K3 accepted every 013 finding and both 014 findings on
  `k3/answers-013-014`; its code and ADR responses are pushed but not merged.
- The native credential claim remains deliberately split. Linux live backend
  execution is proven by logs. The ADR's broader release-CI contract remains
  unimplemented, so no three-platform release-conformance count is claimed.
- Amendment 2's KeyPackage publication, fetch, handout, and deletion
  invariants survived the advisor review. The implementation does not yet
  provide that future lifecycle; §B.1 describes a gate on future
  replenishment/reaping, not a claim that M2 implements it.
- The persisted-state API and atomic obsolete-epoch deletion description in
  issue 014 still matches the store source. The ownership statement needed one
  correction: Core owns the missing drivable client, while K3 owns harness
  wiring after that client exists.
- The two superseded `actor.rs` comments are the only known source/proposed
  amendment rationale mismatches from this session's Amendment 2 claims. They
  are R1 and remain unmodified pending charge's decision.

### R1 contains two superseded source premises

K3's R1 correctly identifies `store/actor.rs:657-659`, which says the caller
cannot distinguish an application message from a commit before decryption.
That is the withdrawn premise from issue 012 DEFECT 3. Amendment 2 §D requires
the content-type-independent wire fingerprint and single-parse transaction
rationale instead.

R1 is incomplete unless it also covers `store/actor.rs:571-576`.
`new_key_package` says a retry has to generate a new KeyPackage because replay
would hand one init key to two joiners. Amendment 2 §B.1 supersedes that
premise: generation replay becomes safe only after publication and fetch are
durably idempotent and uniqueness is enforced across the lifecycle.

Both comments were deliberately left unchanged in the doc-only Amendment 2
batch because the amendment is still **PROPOSED**. Core owns both corrections.
The gate is PR #69 merge: if charge accepts Amendment 2, both source comments
must be corrected before K3's re-review. If charge rejects it, charge must name
the controlling replacement rationale before either comment changes.

### The drivable persisted client belongs to Core

Core accepts ownership of the missing `LocalStore`-backed drivable client.
This is the middle between the responsibilities already recorded in issue 014:

- Core owns the drivable client and the store-facing typed API it needs,
  including a pending-transmission completion disposition that distinguishes a
  prepared self-update from an already-merged commit.
- K3 owns harness wiring once that client exists, including durable transport,
  close/reopen, snapshot timing, and the harness-level FS and PCS criteria.
- Core owns ADR-0007 §6's captured-state differential PCS proof and its
  independent oracle. K3's harness criterion invokes that proof after driving
  the live update.

The gate is M2 close. Neither remaining criterion may be called green until the
Core client exists, K3's harness uses it, and the required negative oracle
passes. A Core-only unit test remains component evidence, not PLAN §9 harness
evidence.

The deterministic member-identity view is also Core-owned, but K3 narrowed the
existing F2 claim to member count and epoch. Its gate is any future claim of
exact membership convergence, no later than M3's membership/commit-ordering
integration; it is not a hidden fourth requirement for the current F2 count.

### Amendment 2 state

Amendment 2 has passed the advisor's verification and the advisor recommends
acceptance. Its KeyPackage lifecycle pins both cases charge requested:
`publish_pending` survives a lost publication response and blocks cleanup, and
`handed_out` is recorded irreversibly before bytes can reach a fetcher while
remaining distinct from successful MLS consumption. Its positive deletion
predicates also make age, pool age, indeterminate network state, and every
possibly published or handed-out state deletion blockers.

It remains **PROPOSED**. Only charge can accept it by committing the status
change under rule 3. No implementation or merge may treat this recommendation
as acceptance.

### Open items, owners, and forcing gates

| Item | Owner | Gate |
|---|---|---|
| R1: correct both superseded `actor.rs` premises | Core | Before PR #69 K3 re-review and merge, after charge's Amendment 2 ruling |
| R2: implement `store_whole_file_rollback_boundary_is_explicit`, or record a charge-approved narrowing | Core implementation; charge decides any narrowing | Before PR #69 merge |
| R3: commit the schema-complete v1 corpus and implement the transactional test-v2 migration, or record a charge-approved narrowing | Core implementation; charge decides any narrowing | Before PR #69 merge |
| Amendment 2 acceptance | charge | Before R1 is finalized and before PR #69 merge |
| ADR-0005 Amendment 2 acceptance from `k3/answers-013-014` | charge | Before the follow-up branch merges or Subscribe acknowledgment is treated as accepted text |
| Re-review R1-R3 | K3 | After Core pushes the complete fixes, before PR #69 merge |
| Merge PR #74 | charge | It records the blocking review and can land now |
| Merge PR #69 | charge | After K3 approves the fixes and required decisions are committed |
| `LocalStore`-backed drivable client and typed pending-completion disposition | Core | Before either remaining M2 criterion can run |
| Harness durable-client wiring and real FS criterion | K3 | After the Core client lands; before M2 close |
| Captured-state differential PCS proof | Core | After the drivable client exists; before M2 close |
| Harness-level PCS criterion invoking the Core proof | K3 | After the Core proof lands; before M2 close |
| Exact member-identity view | Core | Before any exact-membership claim, no later than M3 integration |
| N1 reconciliation outcome/wording plus commit-error injection | Core | Before the first production reconciliation caller, no later than M3 integration |
| N2 verified KT-head API boundary | Core | Before M3 wires KT advancement |
| N3 evidence-depth sub-elements | charge scopes; Core implements accepted scope | Scope decision before M2 close; accepted M2 items before M2 close |
| N4 production feature-graph/evidence exclusion guard | Core defines the graph assertion; K3 owns CI wiring | Before a release workspace build can unify `testing`, and before any PCS extractor lands |
| N5 physical freed-page reconstruction evidence | Core | Before any claim broader than logical provider-row and raw-byte deletion |
| N6 small correctness and naming findings from PR #74 | Core | Before M2 close |
| Assignment of Windows/macOS and release-profile store conformance | charge decides whether CI ownership stays with K3 or moves to Grok; Core reviews the evidence contract | Before implementation starts |
| Windows/macOS and release-profile store conformance | The lane charge assigns | Before any desktop store release or three-platform conformance claim |
| All-desktop-target store latency evidence | Grok owns performance; Core supplies store measurement surfaces | Before any store hot-path performance claim or desktop release gate that depends on it |
| PR #73, superseded by `b772c0f` in PR #69 | charge | Close unmerged once PR #69 preserves the fix |
| K3's `k3/answers-013-014` branch | K3 owns the branch; charge merges | Open its follow-up PR immediately after PR #69 lands |
| ADR-0006 A: role isolation and permission evidence | K3; Core reviews security-adjacent deltas | Before any production deployment uses separate migration/runtime roles |
| ADR-0006 B: minimum-schema and discovery checks | K3; Core reviews security-adjacent deltas | Before mixed-version deployment or a service-specific minimum schema |
| ADR-0006 C: risk-classification enforcement | K3; Core reviews security-adjacent deltas | Before the first `contract` or `data` migration lands |
| ADR-0006 D: rollback and failed-migration evidence | K3; Core reviews security-adjacent deltas | Before rollback or failed-migration Compose behavior is claimed as release evidence |
| M3 commit ordering and F7 | Core | Only after charge closes M2 at the integration checkpoint |
| M3 churn rig and F7 race test | K3 | After Core's M3 commit gate is drivable |
| Device-transparency `KtLeaf` residual | Core | Before device transparency is exposed as a product property |

### Branch state at shutdown

- `core/local-encrypted-store`: pushed, PR #69 open. Its tested code/evidence
  head is `88e1152`; one later status-only shutdown commit follows it. The
  branch is deliberately retained because K3's R1-R3 block merge.
- `k3/pr-69-review` at `02b5025`: PR #74 open; owned by K3 and awaiting charge.
- `k3/store-evidence-provisioning`: PR #73 open but superseded by `b772c0f`
  already in PR #69; charge owns closure.
- `k3/answers-013-014` at `6fd82d8`: pushed without a PR; K3 owns the follow-up
  after PR #69.
- `advisor/shutdown-protocol` (PR #75) and `advisor/status-2026-07-28`
  (PR #76) are advisor-owned and awaiting charge.
- Core owns no merged-but-unswept remote branch. The retired local `sol/*`
  worktrees predate this session and were not touched.
