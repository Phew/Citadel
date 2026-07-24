# Sol status: core lane, M2 in flight

**Agent:** Sol. **Branch prefix:** `sol/`.
**Audience:** a fresh Sol instance with zero memory. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-CORE.md`, then this file.

## Owned surfaces

`citadel-core`, `citadel-proto` as sole merger, `citadel-service-crypto`,
`kt-log`, `docs/protocol/`, and design ADRs. Sol is the blocking reviewer for
crypto, auth-flow, and KT surfaces. K3 reviews Sol's code; Sol reviews K3's.

## Current state

- M1 is closed. ADR-0005 and ADR-0006, including the canonical
  `search_path = public, pg_temp` amendment, are accepted. M2 is not closed.
- PR #38 remains open at `7f2853f` with K3's CHANGES review. Its replacement is
  `sol/m2-citadel-core-respin`, based on current main with the original engine
  commit preserved before the review-fix commit.
- The replacement verifies every added KeyPackage before OpenMLS mutation,
  rejects swapped packages at the initiator, validates the exact MLS leaf key
  binding, processes verified proposal-free staged commits, and keeps
  commit-ordering and proposal handling scoped to M3.
- Local self-updates use prepare, confirm, and abort operations correlated to
  the exact pending commit. A conflicting incoming commit is deferred without
  advancing the epoch.
- The citadel-core focused suite has 26 passing tests. Full workspace format,
  check, strict Clippy, and runnable tests pass locally. PostgreSQL and live
  compose tests remain CI-only.
- PR #39 remains open at `8eaa6c0`. The migration checker delta passed the
  earlier narrow review. The latest lock-cleanup and cancellation delta still
  needs a Sol re-review.
- Repository-cleanup PR #46 is unexpectedly still open at `77507be`. This
  branch carries this status file so the core change and handoff cannot diverge.

## Next actions

1. Open the replacement for PR #38 and request K3's delta-only re-review.
2. Re-review PR #39 only for the `8eaa6c0` lock-cleanup and cancellation delta.
3. After both core and delivery work merge, implement the citadel-core side of
   the M2 exit acceptance criteria with K3's live-stack harness.

## Deferred work

- Do not start device-transparency `KtLeaf` work without explicit direction.
- Do not start ADR-0006 follow-ups A through D without explicit direction.

## Standing corrections

- Comments are encouraged at cryptographic call sites and invariant boundaries.
  Do not revive the superseded no-comments rule.
- The shared GitHub account cannot cast formal approvals. Use labelled review
  comments such as `Sol review — APPROVE` or `Sol review — CHANGES`.
- Work in a dedicated worktree, base branches on main, and use only the `sol/`
  prefix for new branches.
