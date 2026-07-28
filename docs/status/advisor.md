# Advisor status - 2026-07-27 (store built, core seat back to Sol, both lanes working)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## FIRST ACTION next session (written 2026-07-27, both lanes mid-task)

**Verify what the two working lanes push. Nothing else is ahead of it.** Core (Sol) is drafting
ADR-0007 Amendment 2 and verifying the inherited store branch; K3 is fixing the store-evidence
job's provisioning. Neither had landed when this was written.

## Resume queue, in order

1. **Core (Sol): ADR-0007 Amendment 2.** Covers the three confirmed build defects, the two
   smaller findings, a decision on the withdrawn one, and the zero-platform state of §2's
   native-backend conformance evidence. Doc-only, decides nothing, **charge accepts** (rule 3).
   Sol authored the ADR, so it does not accept its own amendment and K3 blocking-reviews it.
2. **K3: the store-evidence job.** `ci.yml` is K3's surface. If a real default collection cannot
   be provisioned reliably on a GitHub runner, that goes to `docs/issues/` rather than weakening
   the test. **A store-evidence job that passes without exercising the daemon is worse than the
   current honest red.**
3. **PR #69 merge decision** once Amendment 2 and the CI job resolve. K3 blocking-reviews the
   store; the advisor does not substitute.
4. **K3: `device_compromise_past_messages_unreadable_fs`**, M2's fifth and final exit criterion,
   once Sol hands over the persisted-state API naming which surface exposes persisted state and
   how obsolete epoch state is deleted. Build to the criterion **as narrowed** (PLAN §9 M2,
   2026-07-26). The reasoning for leaving it unwritten is committed at
   `crates/test-harness/tests/m2_dm.rs:23` and still stands. **No placeholder.**
5. **Integration checkpoint**, then charge declares M2.
6. Still owed by the core lane, older than the store and inherited with the seat: the delta
   re-review of `#39` against `33fcfe9` (5,098 lines, 41 files), and a review of K3's M2 exit-AC
   harness at `295d829` (1,505 lines). The first was originally Sol's own and was never posted
   before charge merged.
7. ADR-0006 follow-ups A-D remain binding, tracked, not started.

## The store landed (PR #69), and the core seat changed twice around it

Opus 5 built the local encrypted client store to the accepted ADR-0007 design: 8,153 insertions
across 36 files, `crates/citadel-core/src/store/`, no `todo!()`, no `#[ignore]`, no placeholder
tests. All three "same PR" items landed with it, and two exceeded the brief:

- the `deny.toml` narrowing is framed as a **decision** with §B.4's reopen conditions written
  into the config itself, so a future reader hitting OpenSSL in `cargo tree` can tell a decision
  from a drift without leaving the file;
- `docs/issues/011` N1 became a real behavioral probe (`SELECT load_extension(?1)` requiring
  `not authorized`), and the build found the reason it was needed: the stock bundle compiles
  `-DSQLITE_ENABLE_LOAD_EXTENSION=1`, so the compile-time pin the ADR assumed does not exist;
- N2's FTS3 row asserts the flags are **present** rather than absent, because A.4's foreclosure
  rests on "compiled but unreachable" and a bundle that actually removed them would need the
  record corrected. That is a sharper reading than the one the advisor asked for.

Then charge returned the seat to Sol on quota restoration (`6306e1d`). The handover was
deliberately staged: Opus fixed CI, filed its findings as `docs/issues/012`, and wrote
`docs/status/core.md` for a reader with zero memory, then stood down. Nothing was orphaned.

## Four defects found in ADR-0007 during the build; three hold

Found by the lane implementing the design, in a document that had already passed an independent
design review and been ACCEPTED. That is the strongest evidence yet that building is a review
method no amount of reading replaces.

- **DEFECT 4 CONFIRMED, and it overturns K3's §D.2.** §6's fail-closed `max_past_epochs` check is
  not implementable as written. `MlsGroupJoinConfig::max_past_epochs` is `pub(crate)`
  (`config.rs:52`), its impl block (`:61-81`) has no accessor, and the public getter at `:191` is
  inside `impl MlsGroupCreateConfig` which opens at `:174`. `configuration()` returns
  `&MlsGroupJoinConfig`. Read from the serde representation instead, which is arguably stronger
  since that is what the provider persists.
- **DEFECT 2 CONFIRMED.** §5's "every state-changing operation requires an `OperationId`" is a
  universal quantifier that conflicts with RFC 9420 single-use KeyPackages: idempotent replay
  would hand two joiners the same init key. Implemented transactional but deliberately unledgered.
- **DEFECT 1 CONFIRMED.** §2 overstates path containment on Windows. `SQLITE_OPEN_NOFOLLOW` is
  inert outside the unix VFS, so the database is path-validated with a TOCTOU window the lock
  ordering narrows but does not close.
- **DEFECT 3 WITHDRAWN, premise false.** The claim was that a caller cannot know whether an
  incoming message is an application message or a commit before decrypting. It can:
  `content_type` is a **cleartext** field of `PrivateMessage` under RFC 9420 §6.3.2
  (`private_message.rs:35`), publicly reachable via
  `MlsMessageIn::try_into_protocol_message()` (`message_in.rs:115`) and
  `ProtocolMessage::content_type()` (`message_in.rs:212`). The one-kind decision may still be
  right, on the basis that an identical retry fingerprinted over raw wire bytes matches
  regardless. It has to be justified that way, not on an impossibility that is not real.

Same shape, both directions, inside one week: the core lane caught a false leg in K3's FTS5
argument on 07-26, and had its own false leg caught on 07-27. Neither was visible to one reader.

## ADVISOR ERROR, 2026-07-27: corrected a correct citation

**The single most instructive error in this project so far, because the method was right and the
input was wrong.**

The advisor "corrected" ADR defect 1's citation from `sqlite3.c:61796` to `:61874-61875`, having
verified it against source. Opus refused the correction and was right.
**`libsqlite3-sys` 0.30.1 ships TWO amalgamations**: `sqlite3/sqlite3.c` (257,673 lines) and
`sqlcipher/sqlite3.c` (261,439 lines). This project compiles the SQLCipher one
(`build.rs:121`, `cfg.file(format!("{lib_name}/sqlite3.c"))`). In that tree `:61795-61797` is
exactly the `SQLITE_OK_SYMLINK` / `SQLITE_OPEN_NOFOLLOW` site and `:61874` is
`ROUND8(pVfs->szOsFile)`, a pager size computation. **The original `61796` was correct.**

Conclusive proof of which tree the repo's citations mean: three of them are SQLCipher-only
symbols that cannot resolve in the plain tree at all, and all three land exactly
(`CIPHER_VERSION_NUMBER 4.5.7` at `:106612`, `sqlcipher_get_mem_security` at `:109000`, the
`load_extension` disallow comment at `:135068`).

The lesson is not "verify against source," which the advisor did. It is **confirm which file you
opened**, especially where a dependency ships two builds of the same amalgamation. The advisor
had lectured, in the same message, that a wrong line number corrodes the correct claims beside
it. `open.rs` now names the amalgamation explicitly so the next reader does not fall in.

## Open and unfixed: native-backend conformance exists on ZERO platforms

The `store · native Secret Service backend` job failed on its first-ever run and the failure is
real. Two tests that never contact the daemon pass; both that write to the live Secret Service
fail with `Locked("Secret Service: no result found")`, because `--unlock` unlocks an *existing*
login keyring and a fresh runner has none. The adapter is correct and classified the backend
state properly; the provisioning is incomplete.

**Every CI job is `ubuntu-latest`. There is no Windows or macOS runner anywhere in the
workflow.** So ADR-0007 §2's native-backend conformance evidence currently exists on **zero**
platforms, not one of three. The outgoing core lane recorded that honestly in both `core.md` and
the PR body rather than letting anyone count Linux as done, and correctly did not fix it, because
`ci.yml` is K3's surface.

Local Windows clippy compiles `windows.rs` and never `secret_service.rs`; CI does the reverse.
**Neither side sees both**, which is why "green locally" and a red CI gate were both honest
reports of the same commit.

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

## Core seat history, and the independence caveat (RESOLVED 2026-07-27)

Sol ran out of usage quota mid-milestone with the store unbuilt, so charge staffed the core seat
with **Claude Opus 5** under rule 12. On the evidence it is the right seat-filling: SWE-bench Pro
79.2% against Sol's 64.6% and Fable 5's 80.3%, Frontier-Bench 43.3% against Sol's 34.4%, $5/$25
per M tokens (half Fable's input price), and a 1M context with no harness cap, where Sol's real
ceiling was 272K against 1M advertised. End-to-end codebase resolution is exactly what building
the store is.

**RESOLVED 2026-07-27: the seat returned to Sol on quota restoration (`6306e1d`), so the core
lane and the advisor are no longer the same model.** The caveat below applied only while both
seats were Opus 5, and it is retained because the seat has moved four times in eleven days and
may move again. **The caveat as it stood: the advisor was also
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
