# Grok status handoff

**Agent:** Grok (Grok 4.5)  
**Updated:** 2026-08-14 (stage 1 of the ADR-0007 release CI matrix)  
**Audience:** a fresh Grok instance with **zero** memory of prior sessions. Read this, then `plans/PLAN.md`, `plans/AGENTS.md`, `plans/PLAN-GROK-4.5.md`, `plans/SHUTDOWN.md`.

---

## Who you are

You are Grok on the Citadel team (E2E encrypted Discord-style chat). Your owned lanes:

| Area | Path / scope |
|------|----------------|
| Infra / scaffolding | M0 (done); ongoing `deploy/`; CI for desktop and the release-profile store matrix |
| Desktop | `apps/desktop` (Tauri 2 + React + TS + Tailwind) |
| Voice | `crates/sfu-gateway` + client encoded transforms (**M7**) |
| Perf | `test-harness/perf` |

**Branch prefix:** `grok/<task>`  
**Worktree:** `…/Citadel/citadel-grok` only. Primary checkout (`…/Citadel/Citadel`) belongs to **charge**. Do not edit primary.

**Process hard rules:** AGENTS.md especially (1) own worktree only, (2) commit early, (8) escalate don't improvise, (10) PR descriptions state milestone / invariants / named tests, (13) **no AI attribution signatures**, (14) end with `plans/SHUTDOWN.md`. Charge alone merges to `main` and accepts ADRs. **This release-CI work does not self-merge** — it is evidence infrastructure for an accepted ADR and routes to charge. Standing: **fmt before push**; never report clean over a red gate.

---

## Housekeeping, confirmed this session

- Worktree clean at start. Nothing of ours unpushed.
- `grok/perf-baselines` **merged** as **#65** (`113b875`, 2026-07-27) and the remote branch is **swept**.
- #65 landed with the self-diff defect fixed (third commit: load `--diff` before `--write` so same-path compare is not a tautology) and a **real committed** `crates/test-harness/perf/baseline.json` (environment: host/OS/arch/CPUs/rustc/git SHA, live compose numbers, not zeros).
- Lane was idle from 2026-07-28 to this assignment, by design.

---

## Current work — release CI matrix, stage 1 only

| Item | Value |
|------|--------|
| Branch | `grok/release-ci-sqlcipher` |
| Base | `origin/main` @ `bc67710` |
| Assignment | charge, 2026-08-14: stage 1 of the three-platform release CI matrix |
| Scope | `.github/workflows/ci.yml` (one new job) and this status file |
| Mode | Evidence infrastructure. No store code. No vendored copy of core's test. |

### What stage 1 is

One job, `store · release-profile pinned SQLCipher`, `runs-on: ubuntu-latest`, that runs `store_release_uses_only_pinned_sqlcipher` under `cargo test --release`. That test reads pinned values back from the **built** artifact: `cipher_version` 4.5.7 community, `cipher_provider`, the absence of `PRAGMA cipher_status`, and the Amendment 1 §A.5 `compile_options` table.

Proving those against the debug artifact is not the same claim as proving them against the artifact you would ship. Today no job anywhere passes `--release`. Stage 1 converts that one ADR claim from "never run in the required profile" to "run," on Linux, for the cost of one job.

### Coordination with PR #69

The named test lives on `origin/core/local-encrypted-store` (PR #69), not on main. This job does **not** vendor a copy. Until `fn store_release_uses_only_pinned_sqlcipher` exists under `crates/citadel-core`, the job is **inert**: it prints that fact and skips the compile. The first ref that contains the function runs it under `--release` and **fails** if cargo's filter matches nothing (`cargo test <filter>` exits 0 on zero matches; PLAN.md §13 forbids treating that as a pass).

### What this is not

- Not Windows. Not macOS. Those are stages 2 and 3; charge approves them separately after stage 1 is green.
- Does not write `store_release_uses_only_the_target_native_credential_backend`. That test does not exist, it is core's store code, and it is assigned to core.
- Does not close M2. M2's two unproven exit criteria are forward secrecy on persisted state and post-compromise security. Neither needs release CI.
- Does not change native credential-backend conformance. That count is still **zero of three** platforms. Stage 1 changes the profile one Linux SQLCipher test will run in, once #69 lands.

### Known hazard

The store links two C libraries. SQLCipher's page codec uses a vendored OpenSSL via `openssl-src`. Release profile changes build flags. If the `--release` build breaks, that breakage is a finding worth filing, not something to paper over with a flag.

---

## Prior (merged, swept)

- Perf harness **#65** (`113b875`): on-demand `perf-baseline` (F2, F4 RTT/throughput, concurrent subscribe, fetch at `MESSAGES_PAGE_LIMIT` 500). Not default CI. `just perf-baseline`.
- PCS oracle SPIKE (`702bbd9`): all four questions YES → ladder rung 1. See `docs/issues/010-pcs-oracle-feasibility.md`.

---

## Carry-forward

1. Worktree only: `citadel-grok`.
2. After this PR merges: wait for charge to approve stage 2 (Windows runner) or stage 3 (macOS runner). Do not add either unasked.
3. Do not write `store_release_uses_only_the_target_native_credential_backend`. Do not touch unowned crates.
4. MSRV **1.95.0**; no AI attribution (rule 13).
5. Real-core desktop wiring is M3 (integration checkpoint).
6. If the release-profile job goes red after #69 lands on openssl-src / build flags: file `docs/issues/`, do not add a skip flag.
