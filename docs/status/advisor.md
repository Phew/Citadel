# Advisor status - 2026-07-26 (ADR-0007 amended, awaiting K3 re-review + charge)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## FIRST ACTION next session

**K3 re-reviews ADR-0007 Amendment 1** (merged `c85f55e`). This is not a formality: the
amendment **corrected a false premise inside K3's own F1 argument**, so K3 must confirm its
staging conclusion survives its corrected premise. Details in queue item 1.

All three prior FIRST ACTIONs are RESOLVED: ADR-0007 was rescued onto main, K3's design review
landed, and Amendment 1 is written and merged (still PROPOSED — merging the text is not
accepting it).

## Resume queue, in order

1. **K3: re-review Amendment 1.** Scope it to the delta. The reason it matters:
   K3's CVE-applicability argument rested on four preconditions, one of which was "the build
   omits FTS5." **On the staged stock bundle that is false.** `libsqlite3-sys` 0.30.1 compiles
   `-DSQLITE_ENABLE_FTS5` unconditionally (`build.rs:129`) and
   `-DSQLITE_ENABLE_LOAD_EXTENSION=1` (`:131`); staging removes the patch, so those flags stop
   being Citadel's to set. The core lane found this by verifying against the pinned crate rather
   than restating the review, said so plainly rather than leaning on the surviving legs, and
   pinned runtime mitigations for the lost compile-time ones (extension loading inert unless
   explicitly enabled, `trusted_schema = OFF`, and the open sequence asserting the flag is off,
   with `store_release_uses_only_pinned_sqlcipher` reading the flag table back from the built
   artifact). K3 should confirm the remaining three preconditions still carry the conclusion,
   and that the runtime mitigations are adequate substitutes. Advisor position: they are, and
   the framing matches the compiled-but-unreachable precedent set for the libcrux advisories in
   `#41`.
   Advisor verification of the amendment, done: every source citation checked exact against the
   pinned crate (`cipher_status` absent, the four replacement pragmas present, `HAS_CODEC` +
   `TEMP_STORE=2` at `:144`, `THREADSAFE=1` at `:136`, the `SQLITE_LoadExtFunc` gate at
   `sqlite3.c:135068-135071` set only at `:142378`). One off-by-one (`:130` for load-extension)
   was corrected by the advisor post-merge.
2. **charge: two decisions, still separate.**
   (a) Accept or reject ADR-0007 **as amended**, after K3's re-review.
   (b) The PLAN §9 M2 acceptance-criterion narrowing, which must NOT ride along inside (a).
   Amendment 1 §E deliberately keeps it out. **Advisor position: the narrowing is correct**,
   because MLS forward secrecy is a property of key material rather than of a retained plaintext
   archive. AGENTS.md reserves acceptance-criterion changes to charge.
3. **Core lane: clear the two inherited reviews** while blocked on acceptance. `#49` first
   (~1,500 lines: the adversarial test and live KT verifier most need a second reader), then
   `#39`. The advisor previously called these "small"; that was wrong and is corrected in
   `docs/status/core.md`. They are real security-adjacent reviews.
4. **Core lane: build the store** once charge accepts. The `deny.toml`
   `wrappers = ["libsqlite3-sys"]` narrowing lands with the build, not before — Amendment 1
   specifies it but correctly does not apply it while the ADR is PROPOSED (rule 3).
5. **K3: `device_compromise_past_messages_unreadable_fs`**, the fifth and last exit criterion,
   once the store lands. Deliberately unwritten until there is persisted state to capture.
6. **Integration checkpoint**, then charge declares M2.
7. ADR-0006 follow-ups A-D remain binding, tracked, not started.

Deliberately NOT started: Grok's real-core desktop wiring. Unblocked, but M3 scope, held by the
integration checkpoint.

## Advisor error corrected 2026-07-26

I characterised the two inherited reviews as "small" in `docs/status/core.md`, which is on main.
They are not: `#49` is ~1,500 lines across three files and `#39` is a full service plus
migrations and DB tests. Left standing, that wording would have pressured a reviewer to skim two
security-adjacent reviews in the lane that most needs a second reader. The core lane pushed back
on it and was right. Corrected in place, with the correction stated rather than silently edited.

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

## Day-close snapshot 2026-07-25

- **main `9afd706`. Zero open PRs. Remote is `main` and nothing else.** Last full CI run on main
  (`295d829`, run 30141369632) green across all seven jobs, log-verified. Every commit after it
  is docs-only and skips CI by design.
- **M1 closed and declared. M2 NOT closed.** Four of five exit criteria are standing CI gates on
  main. The fifth, `device_compromise_past_messages_unreadable_fs`, is blocked on the store,
  which is blocked on ADR-0007's review and acceptance, which is blocked on K3 picking it up.
- **Nothing is in flight and no work is uncommitted.** The ADR-0007 rescue closed the one
  fragile thing from the earlier shutdown snapshot: it had existed only as untracked files in a
  sandbox worktree and is now on main at `7592a26`.
- **Sol is out of usage quota for the week** (charge, 2026-07-25). Its lane is stopped. Its
  progress report, what it owes, and its track-record notes are in `docs/status/core.md`.
- **Three decisions are open and all are charge's:** accept or reject ADR-0007; the separate
  acceptance-criterion change that must not ride along inside that acceptance; and the staffing
  call on who builds the store while Sol is out. See queue items 1 through 3.
- **charge open calls, now carried across four sessions:** LICENSE file (public repo,
  all-rights-reserved by default), gh-token tightening, Citadel trademark check.
- **Local machine housekeeping** (advisor cannot do these): the compose stack may still be up
  (`docker compose -f deploy/docker-compose.yml down -v`, and `-v` drops volumes). Sol has
  several finished worktrees on disk owned by the `CodexSandboxOffline` Windows account, so only
  charge or Sol can remove them. `C:/tmp/Citadel-sol-m2-local-store-adr` is now safe to remove:
  its contents are on main.

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
