# Core lane status — currently Opus 5 (M2: one component left)

**Lane:** security core. **Branch prefix:** `sol/` is retired; use `core/<task>`.
**Audience:** a fresh instance of this lane with zero memory. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-CORE.md`, then this file, then `docs/status/advisor.md`
for the live queue, which is authoritative on ordering.

**This file is named for the lane, not the model, deliberately.** The seat has changed hands
twice in three days (Claude Opus 4.8 through M1, GPT-5.6 Sol on day 5, Claude Opus 5 from
2026-07-26). The authoritative record of who holds it is the roster table in `plans/AGENTS.md`,
which logs every swap under rule 12. Do not rename this file when the model changes.

## Owned surfaces

`citadel-core`, `citadel-proto` (sole merger), `citadel-service-crypto`, `kt-log`,
`docs/protocol/`, and design ADRs. Blocking reviewer of all crypto, auth-flow, and KT surfaces.
**K3 blocking-reviews everything this lane writes; this lane reviews K3's security-adjacent
code. Nobody reviews their own work, and the advisor never substitutes for K3's review.**

## Where M2 stands

Four of five M2 exit criteria are standing CI gates on main and execute on every push:
`f2_three_client_dm_creation`, `f4_send_receive_roundtrip`, `no_plaintext_scan_delivery_tables`,
`pcs_recover_after_update`, `adversarial_ds_swapped_keypackage_rejected`.

The fifth, `device_compromise_past_messages_unreadable_fs`, is **deliberately unwritten** and
must stay that way until this lane's work lands. MLS state is currently in-memory only
(`Provider = OpenMlsRustCrypto`), so an FS test today could only assert that dropping an object
loses the object: it would pass while proving nothing, and a green vacuous test is worse than a
missing one because it looks like evidence. K3 recorded that reasoning in
`crates/test-harness/tests/m2_dm.rs`. **Do not close that gap with a placeholder.**

So M2 needs exactly one thing: the local encrypted client store, plus the FS test that becomes
possible once persisted state exists.

## Immediate task, in order

1. **Fold K3's design-review findings into ADR-0007 as Amendment 1.** The ADR is on main and
   PROPOSED. K3's independent review returned **CHANGES** with two blocking findings, recorded
   in `docs/issues/009-adr-0007-store-design-review.md`. This is the core lane's own ADR, so the
   core lane folds the findings. Amendment 1 is doc-only and decides nothing; charge accepts.
   - **F1: stage the SQLCipher overlay out of M2.** Alternative 2 rejected the stock bundled
     SQLCipher 4.5.7 as "not 4.17.0." K3 answered that from evidence rather than assertion:
     named CVEs against the bundle's SQLite 3.45.3 do exist, but every one requires
     attacker-controlled SQL, an attacker-crafted database file, FTS5, `DEFENSIVE=off`, or
     app-side C-API misuse, and ADR-0007's own design forecloses each precondition. cargo-audit
     over the ADR's exact pinned graph returned zero advisories. So the overlay fails the ADR's
     own stated gate ("a relevant advisory blocks this choice"). Ship M2 on the stock bundle;
     the reproducibility program becomes its own ADR, with a lightweight native manifest plus an
     OSV scan riding along as the tripwire.
     **Wrinkle staging must handle:** `PRAGMA cipher_status` is SQLCipher 4.12.0+, so §3's open
     sequence needs the schema-access probe on 4.5.7.
   - **F2: the ADR collides with `deny.toml` and never says so.**
     `bundled-sqlcipher-vendored-openssl` resolves to `openssl-sys/vendored`, and `deny.toml`
     bans `openssl-sys` **graph-wide**. As written, the ADR cannot build under this project's
     own CI; K3 reproduced `error[banned]` against the real config. The fix K3 proved is
     `wrappers = ["libsqlite3-sys"]` on the ban.
     **Advisor addition, and Amendment 1 must carry it:** that is not merely a lint tweak. The
     ban's stated intent is "TLS is rustls-only; the native-TLS/openssl stack must never enter
     the graph." The narrowing preserves the TLS half of that intent, but it does admit a
     vendored OpenSSL C codebase into `citadel-core`, the one process that holds plaintext.
     Record it in the ADR as a **named accepted consequence** with the reasoning, not as a
     config edit. The alternatives are worse and should be named too: SQLCipher's non-OpenSSL
     backends are LibTomCrypt (less-scrutinized C) or CommonCrypto (macOS only), and avoiding
     SQLCipher entirely means hand-writing an OpenMLS storage provider, which the ADR already
     rejected for sound reasons. The answer is yes, accept it, but a future reader must be able
     to tell a decision from a drift.
2. **Wait for charge to accept.** Rule 3: a decision exists only when committed. Do not start
   the build on a PROPOSED ADR.
3. **Build the local encrypted client store** to the accepted design.
4. **Hand the persisted-state API to K3** for `device_compromise_past_messages_unreadable_fs`.

## Inherited debts from the previous holder of this seat

Two reviews were owed and never delivered when that instance ran out of quota. Both are small
and both should be cleared:

1. The delta re-review of `#39` against `33fcfe9` (the migration lock-cleanup fix). It was never
   posted before charge merged. K3 completed the mirror-image review of `#47` against its merged
   commit and found nothing, so this is the outstanding half of a pair.
2. A review of K3's merged M2 exit-AC harness at `295d829`.

## Approved by K3's review and NOT to be reopened

These were verified and must survive Amendment 1 intact:

- The FS test's exact `ProcessMessageError::ValidationError` → `ValidationError::UnableToDecrypt`
  → `MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)` chain. K3
  reproduced it against openmls 0.8.1 source, and the `PublicMessage` path's `NoPastEpochData`
  divergence confirms the ADR is right to demand an application ciphertext.
- The `max_past_epochs = 0` pin with fail-closed behavior on OpenMLS default drift.
- The PCS design's refusal to substitute a self-referential test, including that it blocks M2
  close rather than degrading the evidence.
- The shared-transaction type argument.
- The keyring `CRED_PERSIST_ENTERPRISE` justification (`windows.rs:246`, confirmed accurate).

## Deferred by design — do not start without explicit direction from charge

- M3 commit ordering and F7. The integration checkpoint gates it.
- The device-transparency `KtLeaf` proto work (ADR-0004's named residual).
- ADR-0006 follow-ups A through D.

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
Three instances so far: the `citadel-core` crate description claiming a local encrypted store
that did not exist, a test doc comment claiming swapped-KeyPackage coverage the test did not
provide, and `plans/PLAN.md` M1 listing "citadel-core keychain integration" as delivered when it
was never built. Every one was caught by someone else reading the code. Treat prose about your
own crate as a claim that has to be true.

A second failure worth knowing: roughly a day of ADR-0007 design work sat uncommitted in a
sandbox worktree because the sandbox could not write the shared Git index and the blocker was
raised at handoff instead of immediately. AGENTS.md rule 2 is not advisory. Commit early, and
escalate a tooling blocker the moment it appears.

## What the previous holders delivered, for provenance

Opus 4.8 (through M1): citadel-proto contracts, the `citadel-service-crypto` facade, `kt-log`
with a Go RFC 6962 differential oracle, ADR-0004, ADR-0005, and the first citadel-core M2 engine.
Sol (day 5): the `#47` respin that fixed both of K3's blocking findings and exceeded them
(initiator-side KT verification before any OpenMLS mutation, staged-commit processing with
update-path verification, typed deferral errors instead of silent drops), plus ADR-0007 and the
catch that PLAN.md's M1 keychain-integration claim was never true.

## Repo facts a fresh instance will not infer

- Work in your own worktree. The primary checkout belongs to charge. Base every branch on `main`,
  never on another open branch. Open PRs early to get CI, and mark them **ready** when mergeable;
  a draft PR cannot be merged.
- CI: `pull_request` is the canonical trigger; push runs only on `main`; docs-only diffs skip CI.
- **A green check is not evidence.** Open the job log and confirm the step actually ran. Every
  real defect this milestone was found by a human-style read of code or logs, not by CI.
- `db-tests` runs against real PostgreSQL 16 and structurally cannot catch runtime-image or
  packaging failures; those surface only in compose-smoke and the canary job.
- Two advisory suppression files are both load-bearing: `deny.toml` (cargo-deny) and
  `.cargo/audit.toml` (cargo-audit). **cargo-audit runs first and can fail the job before
  cargo-deny is ever reached.** Changing one without the other does not work.
- DB test isolation uses a throwaway per-test **database** (ADR-0006), not a per-test schema.
