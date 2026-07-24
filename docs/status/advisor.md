# Advisor status — M2 build in flight (updated 2026-07-24, repo cleanup)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## Resume queue, in order

Both cross-reviews came back **CHANGES** on 2026-07-24. Three blocking findings, all three
independently verified by the advisor against source (not taken on the reviewer's word).
Each agent now fixes its **own** PR, so the two lanes run in parallel and neither blocks the
other.

1. **K3 fixes PR #39** — one blocking finding from Sol's review, CONFIRMED.
   `MIGRATOR.run_direct` (sqlx-core 0.8.6 `migrate/migrator.rs`) calls `conn.lock()` at entry
   but `conn.unlock()` only after every `?` early-return, so a Dirty version, a
   VersionMismatch, an `ensure_migrations_table` failure, or any failing migration returns
   with sqlx's acquisition still held. PostgreSQL session advisory locks need **one unlock per
   acquisition**; our single `pg_advisory_unlock` releases only our own hold. The `tokio::time::timeout`
   backstop is a second path to the same leak, since cancellation drops the future mid-run.
   `migrate_with_bounds` uses `pool.acquire()`, and sqlx returns a dropped `PoolConnection` to
   the pool without a reset, so the leaked lock **persists on a pooled connection** and blocks
   later migrations that land on a different one.
   Companion defect the advisor found while verifying, non-blocking but fix it in the same
   pass: the same drop path leaks `search_path`, `lock_timeout`, and `statement_timeout` onto
   the pooled connection on the **success** path too, and both timeouts leak *looser* than the
   defaults, which would mask hangs in unrelated queries.
   Do NOT reach for `locking = false` — `ci/check_migrations.py` bans it in both the field and
   builder forms, correctly. Fix on the way out instead (`pg_advisory_unlock_all()` plus a
   session reset, on success and error alike), and add evidence: force a migration error under
   the lock, then prove a subsequent `migrate()` on a **different** connection succeeds rather
   than blocking to `lock_timeout`. Cover the cancellation path too.
   Sol's other two findings are closed: the `ci/check_migrations.py` fix PASSED re-review, and
   the "no-comments rule" was REJECTED (AGENTS.md rule 9 encourages comments and supersedes any
   no-comments rule). Do not re-litigate either.
2. **Sol fixes PR #38** — two blocking findings from K3's review, both CONFIRMED.
   - **INV-4 is one-sided.** `add_members` (`crates/citadel-core/src/group.rs`) takes
     `key_packages: &[KeyPackage]` and passes them straight to `mls.add_members` with no KT
     verification and no verifier parameter at all. Verification exists only on the join side.
     That cannot cover the swapped-KeyPackage attack: the Welcome is encrypted to the
     attacker's HPKE init key, so no honest client ever reaches the join check.
     **ADR-0005 §5 explicitly places this on the initiator** ("The initiator, verifying every
     member credential against the KT log before finalizing the group (INV-4), rejects it"),
     so this is an ADR compliance violation, not a design preference. The engine must take the
     verifier on the add path and abort creating no state.
     Advisor addition: the test `join_rejects_non_kt_attested_member` is *documented* as
     pinning the swapped-KeyPackage shape but actually asserts the opposite direction (B
     rejecting A's credential). That false coverage claim is how the gap stayed invisible —
     fix the comment and add a real initiator-side test.
   - **`receive()` drops staged commits.** It matches only `ApplicationMessage` and returns
     `NotApplication` for everything else; `merge_staged_commit`/`StagedCommit` appear nowhere
     in `citadel-core`. The "handling those is M3" comment mis-scopes it: INV-6 *ordering* is
     M3, but commit *processing* is load-bearing for the M2 exit AC, since both
     `pcs_recover_after_update` and the forward-secrecy test drive a self-update commit through
     this path. CI stays green only because the happy path uses `merge_pending_commit`.
   What passed K3's review and should not be re-opened: padding is exactly ADR-0005 (buckets,
   `u32-BE len || content || zero-pad`, pad-then-encrypt confirmed in `send()`/`receive()`);
   proto contracts untouched (no franking field, `seq` server-assigned, `epoch` client-declared);
   join-side INV-4 is genuine; no key material reaches the wire. Non-blocking notes in K3's
   comment: zeroization, seed/pubkey consistency, an `.expect()` in library code.
3. Narrow re-review of each fix delta by the **other** agent (Sol re-reviews #39's fix, K3
   re-reviews #38's fix). Scope to the delta only.
4. charge merges #39 and #38.
5. **M2 EXIT AC** (what actually closes M2): F2 + F4 encrypted DMs end-to-end across 3 clients
   on the live stack, no-plaintext scan on delivery tables, device-compromise forward secrecy
   + PCS, `adversarial_ds_swapped_keypackage_rejected`. Owned by Sol (citadel-core e2e) + K3
   (harness); needs both #38 and #39 merged.
6. ADR-0006 follow-ups A-D remain binding, tracked, not started (A role isolation + bootstrap,
   B startup min-version, C risk-classification enforcement, D remaining probes).

## State

- main 478d943 before this cleanup. M1 closed and declared. M2 in flight, NOT closed.
  ADRs 0001-0006 all ACCEPTED (0006 + Amendment 1 = `search_path = public, pg_temp`).
- Open PRs: #39 (READY, awaiting Sol re-review), #38 (READY, awaiting K3 review). Both green,
  both MERGEABLE / CLEAN. Neither carries a formal GitHub review — the shared account cannot
  cast approvals, so verdicts are relayed in chat and recorded here.
- Desktop shell #3 merged (mock-backed); real-core wiring is a post-#38 follow-up for Grok
  (parked).
- Roster: **Opus REPLACED by Sol** (GPT-5.6 Sol) as the citadel-core + proto + design-ADR
  agent (charge, day 5). K3 = server crates + CI + deny/audit + harness. Grok = desktop
  (parked). `docs/status/opus.md` is renamed to `docs/status/sol.md` by this change.
- Advisor self-corrections on record: (a) "#38 only blocked by deny.toml" was wrong — CI runs
  cargo-audit too, needed `.cargo/audit.toml` (#42); (b) my `search_path` ordering
  `public, pg_catalog, pg_temp` was weaker than Sol's accepted `public, pg_temp`; (c) I called
  the RUSTSEC-2023-0071 precedent a confabulation — it existed in `.cargo/audit.toml` all
  along, I had only checked `deny.toml`.
- charge open calls, still open: **LICENSE file** (public repo, currently all-rights-reserved
  by default, needs charge to pick), gh-token tightening, Citadel trademark check.

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
                            opus.md stranded at day 2. Content salvaged into
                            docs/status/sol.md by this change, so nothing is lost.
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
