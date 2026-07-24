# Advisor status — M2 build in flight (updated 2026-07-24, repo cleanup)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## Resume queue, in order

1. **Sol re-reviews PR #39's two fix deltas.** #39 is READY, CI green (run 30071784448, all
   five jobs pass). Head moved from 84dfa36 to c12a2a5 after shutdown; that delta is
   docs-only (`docs/status/k3.md`, +60 lines) and does not touch the reviewed code. Both of
   Sol's blocking findings were fixed and advisor-verified:
   - preflight now runs UNDER the migration advisory lock (lock id `0x3d32ad9e*CRC32(db)`,
     matches sqlx-postgres 0.8.6 so `run_direct` nests re-entrantly); evidence test
     `canonical_migration_preflight_runs_under_migration_lock`.
   - `ci/check_migrations.py` gained the `CANONICAL_SEARCH_PATH="public, pg_temp"` rule,
     the inline-literal rule, `.set_locking(false)` coverage, and injected probes.
   Sol's third finding (a "no-comments rule") was REJECTED — AGENTS.md rule 9 encourages
   comments and supersedes any no-comments rule. Do not re-litigate.
2. charge merges #39 (delivery-service + ADR-0006 migration CORE land).
3. **K3 does a blocking review of PR #38** (citadel-core, READY at 7f2853f, CI green run
   30064748560). #38 is the only substantial PR never independently reviewed (Opus wrote it,
   Sol inherited and rebased). It is the plaintext boundary — review INV-4 KT-verified join,
   INV-2 key handling, padding, INV-10. Reviewer pairing: Sol reviews K3's code, K3 reviews
   Sol's code, never own code.
4. charge merges #38.
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
