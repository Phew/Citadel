# Grok status handoff

**Agent:** Grok (Grok 4.5)  
**Updated:** 2026-07-26 (PR #65: fmt + unit tests + real baseline run)  
**Audience:** a fresh Grok instance with **zero** memory of prior sessions. Read this, then `plans/PLAN.md`, `plans/AGENTS.md`, `plans/PLAN-GROK-4.5.md`.

---

## Who you are

You are Grok on the Citadel team (E2E encrypted Discord-style chat). Your owned lanes:

| Area | Path / scope |
|------|----------------|
| Infra / scaffolding | M0 (done); ongoing `deploy/`; CI for desktop |
| Desktop | `apps/desktop` (Tauri 2 + React + TS + Tailwind) |
| Voice | `crates/sfu-gateway` + client encoded transforms (**M7**) |
| Perf | `test-harness/perf` |

**Branch prefix:** `grok/<task>`  
**Worktree:** `…/Citadel/citadel-grok` only. Primary checkout (`…/Citadel/Citadel`) belongs to **charge**. Do not edit primary.

**Process hard rules:** AGENTS.md especially (1) own worktree only, (2) commit early, (8) escalate don't improvise, (10) PR descriptions state milestone / invariants / named tests, (13) **no AI attribution signatures**. Charge alone merges to `main` and accepts ADRs. **CI workflow changes do not self-merge.** Standing: **fmt before push**; never report clean over a red gate.

---

## Current work — perf baselines (PR #65)

| Item | Value |
|------|--------|
| Branch | `grok/perf-baselines` |
| Base | `origin/main` @ `29806d3` |
| PR | https://github.com/Phew/Citadel/pull/65 |
| Scope | `crates/test-harness/perf/**`, `justfile`, bin entry, this status file |
| Mode | Measuring only — no optimization, no unowned crate edits |

### Completion criteria (advisor, not relitigated)

1. `cargo fmt --check` green on the harness  
2. One real run: `just dev` then `just perf-baseline`  
3. Resulting `crates/test-harness/perf/baseline.json` committed with environment intact  

### What the harness is

- Binary `perf-baseline`: F2 create/Welcome, F4 RTT + sustained send, concurrent gateway subscribe, fetch at `MESSAGES_PAGE_LIMIT` (500).
- On-demand only (`just perf-baseline`); not default CI.
- PLAN §13: missing stack fails loud (no zeros).
- Unit tests cover pure helpers (`percentiles`, report JSON schema round-trip) so default `cargo test` is not vacuous; live stack numbers are the integration proof.

### Prior

PCS oracle SPIKE **merged** (`702bbd9`): all four questions YES → ladder rung 1. See `docs/issues/010-pcs-oracle-feasibility.md`.

---

## Carry-forward

1. Worktree only: `citadel-grok`.
2. After #65 merges: idle until next assignment (desktop real-core is M3).
3. Do not touch unowned crates; do not tune delivery-service.
4. MSRV **1.95.0**; no AI attribution (rule 13).
5. Real-core desktop wiring is M3 (integration checkpoint).
