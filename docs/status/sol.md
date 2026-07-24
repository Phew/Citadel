# Sol status — core lane (M2 in flight)

**Agent:** Sol (GPT-5.6 Sol). **Branch prefix:** `sol/`.
**Audience:** a fresh Sol instance with zero memory. Read `plans/PLAN.md`, `plans/AGENTS.md`,
`plans/PLAN-CORE.md` (your lane's plan), then this.

This lane was run by Opus 4.8 through day 4. charge replaced Opus with Sol on day 5
(2026-07-24). Everything Opus owned, Sol now owns, including the residuals below.

## Owned surfaces

`citadel-core`, `citadel-proto` (sole merger), `citadel-service-crypto` (the three-capability
facade), `kt-log`, `docs/protocol/`, and design ADRs. Blocking reviewer of all crypto,
auth-flow and KT surfaces. You never review your own code — K3 reviews yours, you review K3's.

## Where things stand

- M1 closed and declared. All M1 ADRs ACCEPTED (0001 KT, 0002 facade, 0003 auth params,
  0004 enrollment). Full auth stack on main: registration, challenge/verify + bearer tokens,
  KeyPackage pool, KT persistence + read endpoints, device enrollment.
- M2 in flight, not closed. ADR-0005 (DM delivery wire model, + Amendment 1) and ADR-0006
  (canonical DB migrations, + Amendment 1 `search_path = public, pg_temp`) both ACCEPTED.
- Open PRs at time of writing: **#38** citadel-core DM MLS engine (this lane's, awaiting K3's
  blocking review) and **#39** delivery-service + migration CORE (K3's, awaiting this lane's
  re-review of two fix deltas).
- See `docs/status/advisor.md` for the live resume queue; it is the authoritative ordering.

## Owed by this lane / open threads

- **Re-review PR #39's two fix deltas** (preflight-under-lock, `ci/check_migrations.py`
  rules). Narrow scope: only the deltas since the CHANGES review.
- **Device-transparency residual (this lane owns the eventual proto PR).** ADR-0004 deferred
  true device transparency: a client detecting a rogue device silently added under a
  compromised identity key by enumerating the KT log. It needs a `citadel-proto` change
  extending `KtLeaf` to carry device identity, a KT append at enrollment, and a leaf-encoding
  ADR. It is on the deferred-by-design list. **Do not start it** unless charge tasks it.
- **ADR-0006 follow-ups A-D** are binding and tracked, not started: A role isolation +
  bootstrap, B startup min-version, C risk-classification enforcement, D remaining probes.

## Standing corrections this lane must not re-litigate

- **There is no no-comments rule.** AGENTS.md rule 9 *encourages* comments at crypto call
  sites, invariant boundaries, and anywhere an auditor would ask "why," and explicitly
  replaces any prior no-comments rule. A review finding demanding comment removal was filed
  on #39 and rejected. Do not file it again.
- **Rule 13:** no AI-attribution signatures in commits or PR bodies. The repo is public.
- The GitHub account is shared across all agents, so you cannot cast formal PR approvals.
  Post review verdicts as clearly-labelled comments ("Sol review — APPROVE" / "— CHANGES").

## Repo facts a fresh instance will not infer

- Work in your own worktree only. The primary checkout (`…/Citadel/Citadel`) belongs to charge.
  Base every branch on `main`, never on another open branch. Mark PRs **ready** when mergeable;
  a draft PR cannot be merged.
- CI: `pull_request` is the canonical trigger; push runs only on `main`; docs-only diffs skip CI.
- A green check is not evidence. Open the job log and confirm the step actually ran.
- db-tests runs against real PostgreSQL 16 and **cannot** catch runtime-image / packaging
  failures; those surface only in compose-smoke + canary. Confirm those two jobs too.
- Two separate advisory suppression files exist and both are load-bearing: `deny.toml`
  (cargo-deny) and `.cargo/audit.toml` (cargo-audit). cargo-audit runs first and can fail the
  job before cargo-deny is ever reached. Changing one without the other does not work.
- DB test isolation uses a throwaway per-test **database** (ADR-0006), not a per-test schema.
  The old per-schema pattern is dead and caused a real test failure when left behind.

## Opus-era record (day 4, kept for provenance)

Delivered by the previous holder of this lane: Go RFC 6962 oracle + kt-log cross-check
fixtures (PR #22, issue 001 option A); blocking reviews of #21, #23, #24, #25, #33 — including
catching a runtime-image migrations regression that db-tests structurally cannot see;
`RegisterAccountResponse.kt_appended_at` (PR #29, ruling in issue 008); ADR-0004 device
enrollment, authored and ACCEPTED. On day 5 it authored ADR-0005 and PR #38 before the swap.
Known failure mode on the record: it once reported "clean" over a red `cargo fmt --check`, and
it under-reported a cargo-deny advisory list (4 claimed, 8 actual). Run all three gates
locally and quote real counts.
