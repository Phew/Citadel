# Advisor status — M2 build in flight (shutdown 2026-07-24)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`. Verify every agent report against the repo/CI logs before endorsing — this milestone every cross-review surfaced something green CI missed.

## Resume queue, in order

1. FIRST ACTION: check whether Sol posted its re-review of PR #39's two fix deltas (relayed at shutdown). #39 is READY at head 84dfa36, CI green (run 30068825207). Both of Sol's blocking findings were fixed and advisor-verified:
   - preflight now runs UNDER the migration advisory lock (lock id 0x3d32ad9e*CRC32(db), matches sqlx-postgres 0.8.6 so run_direct nests re-entrantly); evidence test canonical_migration_preflight_runs_under_migration_lock.
   - ci/check_migrations.py gained the CANONICAL_SEARCH_PATH="public, pg_temp" rule + inline-literal rule + .set_locking(false) coverage + injected probes.
   Sol's third finding (a "no-comments rule") was REJECTED — AGENTS.md rule 9 encourages comments and supersedes any no-comments rule; do not re-litigate (memory: citadel-no-comments-rule-is-dead).
2. When Sol approves #39 → charge merges #39 (delivery-service + ADR-0006 migration CORE land).
3. Then K3 does a blocking review of PR #38 (citadel-core, READY at 7f2853f, CI green run 30064748560). #38 is the only substantial PR never independently reviewed (Opus wrote it, Sol inherited+rebased). It is the plaintext boundary — review INV-4 KT-verified join, INV-2 key handling, padding, INV-10. Reviewer pairing: Sol reviews #39 (K3's code), K3 reviews #38 (Sol's code) — never own code.
4. Then charge merges #38.
5. Then the M2 EXIT AC (what actually closes M2): F2 + F4 encrypted DMs end-to-end across 3 clients on the live stack, no-plaintext scan on delivery tables, device-compromise forward-secrecy + PCS, adversarial_ds_swapped_keypackage_rejected. Owned by Sol (citadel-core e2e) + K3 (harness), needs both #38 and #39 merged.
6. ADR-0006 follow-ups A-D remain binding, tracked, not started (A role isolation+bootstrap, B startup min-version, C risk-classification enforcement, D remaining probes).

## State at shutdown

- main 8a07668. M1 closed+declared. M2 in flight, NOT closed. ADRs 0001-0006 accepted (0006 + Amendment 1 = search_path public, pg_temp).
- Open PRs: #39 (READY, awaiting Sol re-review), #38 (READY, awaiting K3 review). Both green.
- Desktop shell #3 merged (mock-backed); real-core wiring is a post-#38 follow-up for Grok (parked).
- Roster: Opus REPLACED by Sol (GPT-5.6 Sol) as the citadel-core + proto + design-ADR agent (charge, day 5). K3 = server crates + CI + deny/audit + harness. Grok = desktop (parked).
- Advisor self-corrections logged this run: (a) "#38 only blocked by deny.toml" was wrong — CI runs cargo-audit too, needed .cargo/audit.toml (#42); (b) my search_path ordering public,pg_catalog,pg_temp was weaker than Sol's accepted public,pg_temp; (c) I called RUSTSEC-2023-0071 precedent a confabulation — it existed in .cargo/audit.toml, I'd only checked deny.toml.
- charge open calls, still open: LICENSE file (public repo, all-rights-reserved), delete stale origin/advisor/setup, gh-token tightening, Citadel trademark check.

## Suppression config (both needed — cargo-audit AND cargo-deny run)
- deny.toml: 8 ignores (#41). .cargo/audit.toml: 6 fatal ignores + pre-existing RUSTSEC-2023-0071 (#42). All the OpenMLS/hpke-rs libcrux chain, off the runtime crypto path; revisit on an hpke-rs optional-dep fix.
