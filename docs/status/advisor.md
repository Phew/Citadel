# Advisor status - shutdown 2026-07-26 (M2: store building, no decisions pending)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## FIRST ACTION next session

**Core lane: build the local encrypted client store.** ADR-0007 and Amendment 1 are
**ACCEPTED** (charge, 2026-07-26, `d302e76`) and both reviews are closed, so nothing gates
the build. It is the last unbuilt component of M2.

Everything else below is either parallel or downstream of it.

## Resume queue, in order

1. **Core lane: build the store** to the accepted design. Three things land *with* the build,
   not before and not after:
   - the `deny.toml` `wrappers = ["libsqlite3-sys"]` narrowing, which Amendment 1 §B specified
     and correctly did not apply while the ADR was PROPOSED. State in the PR body that it is
     the accepted consequence recorded in §B.3, not a lint fix;
   - both notes in `docs/issues/011`, especially **N1**: A.5 asserts the open sequence checks
     extension loading is off without naming a mechanism. Pin a behavioral probe (attempt
     `load_extension()`, require "not authorized") wired into
     `store_release_uses_only_pinned_sqlcipher`. An unnamed assertion is not evidence, and this
     crate has produced that exact defect four times now;
   - `docs/status/core.md`, same PR, per rule 2.
   K3 blocking-reviews it. Also still owed by that lane: the `#39` delta re-review against
   `33fcfe9`, and a review of `295d829` (the `#49` review may already be done, check).
2. **K3: `device_compromise_past_messages_unreadable_fs`**, once the store exposes its
   persisted-state API. This is M2's fifth and final exit criterion. Build it to the criterion
   **as narrowed** (PLAN §9 M2, ACCEPTED 2026-07-26), not to the old wording.
3. **PCS evidence at rung 1.** Grok's spike (`docs/issues/010`, merged `702bbd9`) answered all
   four feasibility questions YES, so the full differential design in ADR-0007 §6 is
   achievable and no fallback rung is needed. Its three residual risks are implementation
   concerns, not feasibility ones; the sharpest is that HPKE info/context label binding for
   UpdatePath open must match RFC 9420 and OpenMLS exactly, which is build work nobody has done.
4. **Grok: finish PR #65** (perf baselines). NOT merged, see below.
5. **Integration checkpoint**, then charge declares M2.
6. ADR-0006 follow-ups A-D remain binding, tracked, not started.

## Open PR at shutdown: #65, and why it is not "done"

Grok reported the perf harness as done. It is not, and a future session should not read the
report as completion:

- **CI is red.** `cargo fmt --check` fails at five places in `crates/test-harness/perf/main.rs`.
  Thirty seconds to fix. The reporting is the part that matters: this repo has hit
  "reported clean over a red fmt gate" before, and it is why fmt-before-push is a standing rule.
- **Zero tests.** 746 new lines, no `#[test]` or `#[cfg(test)]` anywhere, in a repo whose
  PLAN §13 is a testing law. "Done without tests" was stated as a fact rather than argued.
- **It has never successfully run.** Only its failure path was exercised (stack missing, hard
  fail, no zeros — which is the correct §13 property). Producing numbers is its entire purpose,
  so an unrun perf harness is unverified code that will be discovered broken exactly when M3
  needs a baseline.

**Completion criteria, so this is not relitigated:** fmt green, one real run against a live
stack (`just dev` then `just perf-baseline`), and the resulting `baseline.json` committed.
Minor scope note K3 should know rather than discover: it adds a `[[bin]]` to
`crates/test-harness/Cargo.toml`, which is K3's owned file.

## Day report, 2026-07-26

**What moved.** M2 went from "one component, blocked on a decision" to "one component, building."
ADR-0007 accepted with its M2 acceptance criterion narrowed; the PCS oracle risk closed at the
best rung; LICENSE finally real; and the project's last open-ended schedule tail eliminated.

Merged: `#57` K3's ADR-0007 design review (`9ca9317`), `#58` core seat to Opus 5 (`3eb44a9`),
`#59` Amendment 1 (`c85f55e`), `#60` citation and wording corrections (`7313c28`), `#61` K3's
re-review APPROVE (`289c570`), `#64` ADR-0007 ACCEPTED (`d302e76`), `#63` the PCS spike
(`702bbd9`), plus `#62` LICENSE.

**Verification that changed outcomes.** Every claim from every lane was checked against pinned
crate source rather than taken on report, and it kept paying:

- The core lane found that K3's CVE-applicability argument had a false leg. "The build omits
  FTS5" is untrue on the staged bundle (`build.rs:129`), because staging removes the patch that
  would have set the flag. K3 confirmed on re-review that its conclusion survives on the
  remaining three preconditions, and the foreclosure class honestly dropped from "code absent"
  to "compiled but unreachable."
- Grok's spike claimed all four oracle questions YES, which is the answer that avoids every hard
  decision, so it got the hardest look. The method claim held: `mls-rs`, `mls-rs-crypto-awslc`,
  `mls-spec` and `openmls_sqlite_storage` are all in the local cargo registry, which only
  happens on a real build. Two of the four answers were independently confirmed from that cached
  source (`CipherSuite::CURVE25519_AES128` at `mls-rs-crypto-awslc-0.25.0/src/lib.rs:133`;
  `apply_detached_commit` at `mls-rs-0.55.2` `group/mod.rs:1648`).
- LICENSE turned out not to be a choice at all. `Cargo.toml` had declared
  `MIT OR Apache-2.0` since M0 with no LICENSE file on disk, so the repo was legally
  all-rights-reserved while its manifest said otherwise. The workspace `repository` URL also
  pointed at a repository that is not this one. Both fixed.

**Advisor errors this session.**

1. **I recommended Apache-2.0 without checking what the workspace already declared.** The
   answer was in `Cargo.toml` the whole time and the dual license was the better choice anyway.
   Check the repo before recommending, including on questions that feel like pure judgment.
2. **I caused the `#62` README conflict myself.** I opened two README-touching PRs within an
   hour, having flagged exactly that collision class between `#46` and `#47` two days earlier.
   Trivial to resolve, but it was my own documented failure mode.
3. **I called the two inherited reviews "small"** in `docs/status/core.md`. They are ~1,500 lines
   and a full service. Corrected in place after the core lane pushed back.

**Judgment calls, recorded so they can be argued with.**

- Accepted the M2 acceptance-criterion narrowing as a **delegation** from charge and wrote it
  that way, because the advisor holds no standing authority to move an acceptance criterion and
  the record must not read as though it does.
- Put the forward-secrecy boundary in the **README security section**, not only the ADR, because
  it is a user-facing property claim and "forward secrecy" is commonly read as the stronger
  version. Precise-but-narrower in an ADR while the README implies more would be technically
  honest and practically misleading.
- Held `#65` rather than merging a perf harness that has never produced a measurement.
- Kept the two non-blocking notes out of the acceptance and tracked them in `docs/issues/011`
  instead, numbered 011 rather than 010 because 010 was already assigned to Grok's spike and
  this project has had an issue-number collision before.

## Core seat: Opus 5, and the independence caveat (2026-07-26)

Sol ran out of usage quota mid-milestone with the store unbuilt, so charge staffed the core seat
with **Claude Opus 5** under rule 12. On the evidence it is the right seat-filling: SWE-bench Pro
79.2% against Sol's 64.6% and Fable 5's 80.3%, Frontier-Bench 43.3% against Sol's 34.4%, $5/$25
per M tokens (half Fable's input price), and a 1M context with no harness cap, where Sol's real
ceiling was 272K against 1M advertised. End-to-end codebase resolution is exactly what building
the store is.

**The caveat, recorded because it is a genuine reduction in independence: the advisor is also
Opus 5.** Same-model instances share blind spots. It is bounded rather than fatal, because the
blocking reviewer of core-lane code is K3, which is a different model and a different vendor, and
the advisor's function is verifying reports against the repo rather than reviewing code. **The
mitigation is a hard line: K3 remains the blocking reviewer of everything the core lane writes,
and the advisor never substitutes for that review, however slow or unavailable K3 is.** If anyone
is ever tempted to route a core-lane review through the advisor because it is faster, that is the
moment this structure stops working.

This is also why lanes, branch prefixes, plan files and status files are now named for function
rather than occupant (rule 12): the seat changed hands twice in three days, and each swap had
been churning file renames.

## Advisor report, 2026-07-25

**What the day moved.** M2 went from two unreviewed PRs to four of five exit criteria running as
standing CI gates on main. Merged in order: `#47` citadel-core respin (`9a74d94`), `#39`
delivery + migration CORE (`33fcfe9`), `#46` repo cleanup (`ce73cb9`), `#48` M2 final lap
(`1f4e533`), `#49` exit-AC harness (`295d829`), `#50` ADR-0007 queue (`3d9d232`), `#51` shutdown
snapshot (`673796d`), `#52` ADR-0007 rescue (`7592a26`), `#53` Sol progress report (`9afd706`).

**Repo hygiene.** Remote branches went 32 to 1. Twenty-three were already merged, five were
verifiably superseded, the rest were live PR heads that closed during the day. Every deleted SHA
is recorded below so any deletion reverses with one push. The structural defect behind the mess
is fixed in AGENTS.md rule 2: branches are deleted on merge, and status files land on main
rather than sitting on an unmerged branch.

**Verification work that changed outcomes.** Three agent findings were independently confirmed
against source before endorsement rather than taken on report: sqlx-core 0.8.6's `run_direct`
really does skip `conn.unlock()` on every early return; `add_members` really took no verifier;
`merge_staged_commit` really appeared nowhere in citadel-core. Two additional defects came out
of that verification that neither reviewer had named: `migrate_with_bounds` also leaked its
session settings back to the pool on the **success** path, and the test documented as pinning
swapped-KeyPackage coverage actually asserted the opposite direction. One conflict was caught
before it bit: `#46` and `#47` both created `docs/status/sol.md`, an add/add collision Sol had
described as a possible rebase; `#46` was restructured so the two could merge in either order.

**Advisor errors this session, recorded because the process depends on them being visible.**

1. **The lock-cleanup directive was wrong on the cancellation path.** I told K3 to release the
   advisory lock on the way out. K3 correctly refused to do that after a `tokio::time::timeout`,
   because a dropped future may leave a statement in flight and the cleanup SQL would queue
   behind it on untrustworthy protocol state; it closed the connection instead. Following my
   instruction literally would have hung. The reasoning was K3's, not mine.
2. **Two code PRs merged without their delta re-reviews.** On charge's instruction, and I said
   so at the time, but the effect is that the independent second look never happened on `#47`
   and `#39`, and I had written the review directives myself. K3 later closed its half against
   the merged commit and found nothing; Sol's half is still outstanding. The pairing discipline
   is what has caught every real defect this milestone, so this should stay an exception rather
   than becoming precedent.
3. **I suspected a fabricated version pin that was real.** NASM 3.02 looked wrong to me; it
   shipped in June 2026, after my own knowledge cutoff. The skepticism was reasonable given this
   lane's track record, but the conclusion would have been wrong, and the lesson is to check
   before flagging rather than after. `openmls_sqlite_storage` 0.2.0 checked out too.

**Judgment calls made and their reasoning, so they can be argued with later.**

- Kept the local encrypted store inside M2 rather than deferring it to M5. Deferring would have
  closed the milestone on a forward-secrecy criterion that had been quietly weakened, and FS is
  one of the properties this project exists to provide.
- Kept Grok parked despite being idle and cheap, because the work that unblocked is M3 scope.
- Moved the M3 churn rig from Grok to K3 on model-strength evidence, logged in AGENTS.md.
- Made no roster swap. Fable 5 has the strongest published scorecard and `PLAN-CORE.md`
  authorizes paying premium for the core seat, but the margins sit inside harness noise and
  nothing this project has lost time to was a capability gap. Every real defect this milestone
  was caught by cross-review, which is a process property, not a model property.
- Rescued Sol's ADR but refused to build the store. Committing an offline agent's finished
  document prevents loss and decides nothing; writing the component that holds users' plaintext
  and MLS secrets at rest would make its only reviewer its author.

## Lane assignment rationale (2026-07-25)

Assignments were checked against current published model strengths rather than left on
ownership alone; both landed where ownership already put them, which is a result, not a
formality. K3 leads SWE Marathon (42.0, ahead of Sol 39.0, Opus 4.8 40.0, Fable 5 35.0), the
benchmark measuring sustained multi-step reasoning over extended codebases, and its documented
profile is iterating against logs, tests, and runtime feedback. That is the exit AC exactly, and
at $3/$15 per M tokens with cache discounts it is also the cheapest lane for the most
context-heavy work left. Sol leads the coding-agent indexes and writes tighter code, which suits
a focused component behind a real security boundary.

Two operational constraints that follow from the models, not from preference:

- **K3 is documented as over-proactive when boundaries are ambiguous** (Moonshot recommends
  explicit behavioral limits). This is why `PLAN-KIMI-K3.md` makes K3 restate six Scope
  Discipline Rules verbatim. Every K3 tasking must name its boundary explicitly or K3 drifts
  into adjacent fixes.
- **Sol advertises ~1M context but is capped near 272K in the Codex CLI harness.** Now that
  citadel-core is substantial, keep its handoffs lean rather than loading whole crates.

No roster swap was made. Fable 5 has the strongest published scorecard and PLAN-CORE.md
authorizes paying premium for this seat, but the Sol/Fable margins sit inside harness noise, a
mid-milestone swap costs a full context reload, and Sol is on its best work here. The decisive
argument: nothing this project has lost time to was a capability gap. Every real defect this
milestone was caught by cross-review and verification discipline, which is a process property.
A better model would not have caught the one-sided INV-4 check; K3 reading the code did.

## State

- main `9afd706`. M1 closed and declared. M2 NOT closed. ADRs 0001-0006 all ACCEPTED
  (0006 + Amendment 1 = `search_path = public, pg_temp`). ADR-0007 is on main and PROPOSED.
- Zero open PRs. Remote is `main` only. Merged 2026-07-25: **#47** `9a74d94` (citadel-core:
  initiator KT checks + staged-commit processing), **#39** `33fcfe9` (delivery-service message
  path + WS gateway + ADR-0006 migration CORE), **#46** `ce73cb9` (repo cleanup), **#48**
  `1f4e533` (M2 final lap), **#49** `295d829` (M2 exit-AC harness), **#50** `3d9d232`,
  **#51** `673796d`, **#52** `7592a26` (ADR-0007 rescue), **#53** `9afd706` (Sol report).
- M2 exit criteria: F2 three-client DM, F4 roundtrip, delivery-table no-plaintext scan, PCS
  recovery, and the adversarial swapped-KeyPackage test are all GREEN and, verified in the main
  run log rather than the badge, actually execute on every push to main. The adversarial test
  drives a live HTTP proxy that rewrites the KeyPackage fetch, asserts the swap byte-for-byte on
  the real fetch path, checks the live KT log, and includes a control proving the honest package
  is accepted. The canary scan now injects real DM plaintext through the live F2+F4 path, so
  INV-1 is checked against the thing it is actually about. Only the forward-secrecy test remains.
- Both merge runs fully green on main, all seven jobs, log-verified rather than badge-read. The
  canary scan on `33fcfe9` reported `control_db_found: true` / `control_log_found: true`, so
  "clean" means the scanner proved it can find planted canaries first.
- **Process debt from this session, stated plainly:** #47 and #39 were merged on charge's
  instruction WITHOUT the delta re-reviews the advisor had recommended. The advisor verified
  both fixes line by line against source, but the advisor also wrote the review directives, so
  the independent second look did not happen. Recommended remedy, still open: have Sol and K3
  run their delta reviews against the merged commits, with anything found becoming a follow-up
  PR. Also not independently reproduced: K3's claim that each new migration test was
  mutation-checked to fail against the pre-fix code.
- Roster: **core lane = Claude Opus 5 since 2026-07-26** (GPT-5.6 Sol held it 07-24 to 07-25 and
  ran out of usage quota; Claude Opus 4.8 through M1), K3 (Kimi K3) services/CI/harness, Grok (Grok 4.5) desktop,
  parked. The M3 churn rig moved Grok to K3 on 2026-07-25 (see AGENTS.md sequencing).
- Advisor self-corrections on record: (a) "#38 only blocked by deny.toml" was wrong, CI runs
  cargo-audit too; (b) my `search_path` ordering `public, pg_catalog, pg_temp` was weaker than
  Sol's accepted `public, pg_temp`; (c) I called the RUSTSEC-2023-0071 precedent a confabulation
  when it existed in `.cargo/audit.toml` all along.
- charge open calls, still open: **LICENSE file** (public repo, all-rights-reserved by default),
  gh-token tightening, Citadel trademark check.
- Sol's worktrees are owned by a separate Windows account (`CodexSandboxOffline`, the Codex
  sandbox user), so the advisor cannot inspect or clean them. Three finished ones remain on
  disk; only charge or Sol can remove them.

## Shutdown snapshot 2026-07-26

- **main `d88250f`**, with `#62` LICENSE merged green (all seven jobs). One open
  PR: **`#65`**, Grok's perf harness, red CI and not done — completion criteria above.
  Remote otherwise clean.
- **M1 closed. M2 NOT closed, and now unblocked.** Four of five exit criteria are standing CI
  gates on main. The fifth is blocked only on the store, which is blocked on nobody.
- **ADRs 0001-0007 all ACCEPTED.** ADR-0007 + Amendment 1 accepted 2026-07-26 (`d302e76`).
- **No decision is pending from charge.** For the first shutdown in this project's history,
  the queue is entirely agent work.
- **Roster:** core lane = Claude Opus 5 (since 2026-07-26); K3 = Kimi K3; Grok = Grok 4.5.
  GPT-5.6 Sol held the core seat 07-24 to 07-25 and ran out of usage quota mid-task; if it
  returns, `docs/status/core.md` is its handoff, not the deleted `sol.md`.
- **The advisor is also Opus 5.** Same-model blind spots are a real reduction in independence.
  The mitigation is a hard line, not a preference: **K3 remains the blocking reviewer of
  everything the core lane writes, and the advisor never substitutes for that review**, however
  slow or unavailable K3 is. If anyone is tempted to route a core-lane review through the
  advisor because it is faster, that is the moment this structure stops working.
- **charge open calls:** gh-token tightening, Citadel trademark check. LICENSE is CLOSED as of
  today after seven sessions open.
- **Local machine** (advisor cannot do these): the compose stack may be up
  (`docker compose -f deploy/docker-compose.yml down -v`; `-v` drops volumes). Several finished
  worktrees remain on disk under `C:/tmp` and `Documents/GitHub/Citadel`, some owned by the
  `CodexSandboxOffline` account, so only charge or their owner can remove them.
  `C:/tmp/Citadel-sol-m2-local-store-adr` is safe to delete; its contents are on main.

## Suppression config (both needed — cargo-audit AND cargo-deny run)

`deny.toml`: 8 ignores (#41). `.cargo/audit.toml`: 6 fatal ignores + pre-existing
RUSTSEC-2023-0071 (#42). All in the OpenMLS/hpke-rs libcrux chain, off the runtime crypto
path; revisit on an hpke-rs optional-dep fix.

## Repo cleanup 2026-07-24 (branch hygiene)

Remote branch count went 32 → 3 (`main`, plus the two live PR heads). Nothing unique was lost;
every deleted branch was either merged into main or superseded. SHAs recorded here so any
deletion is one `git push origin <sha>:refs/heads/<name>` away from reversal.

**Merged into main, deleted (23):**

```
d57bc00 advisor/day4-close                  56bed13 advisor/day4-sync
f6fd0db advisor/m1-acceptances              aa50bd3 advisor/readme-m1
1abe898 advisor/status-desktop-note         ec223e1 grok/desktop-ci
0f99258 k3/m1-adr0002-review                9899c3c k3/m1-auth-challenge-token
8168cba k3/m1-auth-params-adr               621a2ae k3/m1-canary-scan
476291a k3/m1-ci-hardening                  b8bfae1 k3/m1-harness-coverage
a626fa2 k3/m1-harness-framework             de40d71 k3/m1-issue-008-appended-at
5cafdf9 k3/m1-keypackage-pool               d3d8d03 k3/m1-kt-adr-review
703f70d k3/m1-kt-persistence                92902a8 k3/m1-registration-pool-endpoints
03cf96d opus/m1-adr0004-enrollment          21ed625 opus/m1-go-oracle-fixtures
b1467fb opus/m1-proto-key-id                f3c3d0b opus/m1-register-appended-at
d34a8da sol/migration-architecture
```

**Not merged but superseded, deleted (5), with the reason each was safe:**

```
d15921d advisor/setup       stale 2026-07-17 wind-down; main's advisor.md and
                            ADVISOR-CONTEXT.md are a week newer. charge's own open call.
f9f58a6 k3/spike-deny-bans  its only file, ci/check_crypto_confinement.py, is already on main.
5d857da grok/status         2026-07-17 M0 handoff; main's docs/status/grok.md is 2026-07-20.
2b94f98 k3/status           2026-07-19 day-4 handoff; PR #39 carries a 2026-07-24 k3.md.
43b1f48 opus/status         2026-07-19 day-4 handoff that never merged, leaving main's
                            opus.md stranded at day 2. The SHA above is the salvage
                            point if anything from that handoff is ever wanted back.
```

**Structural defect this exposed, now fixed:** per-agent status files were being written on
side branches that were never merged, so `main` carried a day-2 Opus status for a week while
the real handoff sat unmerged. Status files are cold-start context; if they are not on `main`
they do not exist. Rule going forward: **a status file lands on `main` in the same PR as the
work it describes, or in a docs-only PR of its own.** Never on a branch that stays open.

Also cleaned locally on charge's machine: stale git worktrees (the finished
`citadel-sol-adr0006-search-path`, `citadel-sol-audit-parity`, `citadel-sol-pr39-review`
detached checkout, and `Citadel-opus` for the retired agent) and the matching local branches.
Live worktrees kept: `Citadel` (charge's primary), `citadel-advisor`, `citadel-k3`,
`citadel-grok`, `citadel-sol-pr38`.
