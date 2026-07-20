# Opus status — end of 2026-07-19 (day 4, M1 exit)

For a fresh Opus instance with zero memory of today. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-OPUS-4.8.md` first, then this. You are the
security core owner and blocking reviewer of all crypto surfaces.

## Where things stand

**M1 is complete and its exit evidence is being committed.** main is at
`d2768c8` (PR #33 device enrollment merged). The M1 exit AC run on main
(`29713459939`) was in progress at shutdown; the advisor verifies it at day-5
start. All four M1 ADRs are ACCEPTED (0001 KT, 0002 facade, 0003 auth params,
0004 enrollment). Full auth stack shipped: registration, challenge/verify +
bearer tokens, KeyPackage pool, KT persistence + read endpoints, device
enrollment. Harness M1 AC exercises 3 accounts × 2 devices end-to-end against
the live stack, with client-side KT inclusion verification.

**Rule 13 is in force:** no AI-attribution signatures in commits or PR bodies
(no `Co-Authored-By`, no "Generated with Claude Code"). The repo is public.
Shared GitHub account across all agents → you cannot cast formal PR approvals;
post review verdicts as clearly-labelled comments ("Opus review — APPROVE").

## What I did this day (all merged unless noted)

1. **Go RFC 6962 oracle + kt-log cross-check fixtures** (issue 001 opt A) —
   PR #22. `crates/test-harness/oracles/merkle-go/` (independent Go impl,
   written from the RFC, not ported from tree.rs) + committed fixture corpus +
   `crates/kt-log/tests/go_oracle_fixtures.rs`. Reproduces the published CT
   golden roots; byte-stable regen for K3's diff CI. **Go is NOT installed on
   this machine** — I used portable Go 1.22.5 in scratchpad; needed only to
   regenerate fixtures, not to build/CI.
2. **Reviews:** confinement-wiring #21 (APPROVE), challenge/token #23 (approved
   logic; blocked a runtime-image migrations regression — fixed with
   `sqlx::migrate!` — then cleared), KT-persistence #24 (APPROVE),
   registration+pool #25 (APPROVE), device-enrollment #33 (APPROVE — the last
   human-side M1 gate). Standard: open the CI logs, never trust check colour.
3. **proto `kt_appended_at`** — PR #29. `RegisterAccountResponse.kt_appended_at`
   so the F1 step-5 client self-inclusion check can rebuild its own KtLeaf
   (the server-assigned timestamp is in the signed leaf pre-image). K3 recorded
   the ruling in issue 008 (PR #30).
4. **ADR-0004 device enrollment** — authored (PR #32), **ACCEPTED** by charge.
   Enrollment = bearer token (ADR-0003 §3) + `DeviceEndorsement` by that same
   device's key + identity-signed `DeviceCredential`, one `devices` INSERT,
   **no KT append**, no proto change. See the ADR for the full rationale.

## Owed by me / open threads

- **Device-transparency residual (I own the eventual proto PR).** ADR-0004 §"KT
  log" deferred, by charge's acceptance, true device transparency (a client
  detecting a rogue device silently added under a compromised identity key by
  enumerating the KT log). It would need a `citadel-proto` change extending
  `KtLeaf` to carry device identity + a KT append at enrollment + a
  leaf-encoding ADR. It is on the deferred-by-design list. **DO NOT start it**
  unless charge tasks it for a post-M1 milestone — deferred means deferred.
- Nothing else outstanding. No M2 design started (day-5 tasking comes fresh).

## Owned surfaces (reminder)

`citadel-proto` (sole merger), `citadel-service-crypto` (the three-capability
facade), `kt-log`, `docs/protocol/`, ADRs. Blocking reviewer of all crypto /
auth-flow / KT surfaces. K3's security-adjacent code gets your blocking review;
you never review your own.

## Repo facts a fresh instance won't infer

- Worktree: `C:\Users\charge\Documents\GitHub\Citadel\Citadel-opus` (git
  worktree of charge's primary checkout). Always `git fetch` + confirm with
  `git rev-parse --show-toplevel` before touching anything; base new branches on
  `main`, never on another open branch.
- CI (post PR #26): `pull_request` is the canonical trigger; push runs only on
  `main`; docs-only diffs skip CI. Actions minutes are unlimited (repo public).
- db-tests runs against real PostgreSQL 16; it CANNOT catch runtime-image /
  packaging failures (those surface only in compose-smoke + canary) — always
  confirm those two jobs too, as the #23 migrations regression taught.
- Test isolation for DB tests uses a fresh per-test schema (`CREATE SCHEMA` +
  `search_path`) because `kt_leaves.seq` is one global BIGSERIAL per database.
