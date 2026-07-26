# Grok status handoff

**Agent:** Grok (Grok 4.5)  
**Updated:** 2026-07-26 (PCS oracle SPIKE done; perf baselines next)  
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

**Process hard rules:** AGENTS.md especially (1) own worktree only, (2) commit early, (8) escalate don't improvise, (10) PR descriptions state milestone / invariants / named tests, (13) **no AI attribution signatures**. Charge alone merges to `main` and accepts ADRs. **CI workflow changes do not self-merge.**

---

## Current work — PCS oracle SPIKE (this PR)

| Item | Value |
|------|--------|
| Branch | `grok/pcs-oracle-spike` |
| Base | `origin/main` @ `289c570` |
| Scope | `docs/issues/010-pcs-oracle-feasibility.md` + `docs/status/grok.md` only |
| Mode | SPIKE evidence, no implementation |

### Result (charge ladder)

ADR-0007 §6 pins independent PCS oracles. Probe (throwaway crate outside repo, deleted after) answered all four load-bearing questions **YES**:

1. `mls-rs-crypto-awslc` 0.25.0 supports suite id 1 (`CURVE25519_AES128`).
2. `mls-rs` 0.55.2 exposes `commit_detached` → `(CommitOutput, CommitSecrets)`; clone can be denied secrets.
3. `mls-spec` 2.0.1 exposes per-node `UpdatePathNode.encrypted_path_secret: Vec<HpkeCiphertext>`.
4. `openmls_sqlite_storage` 0.2.0 persists HPKE private keys + `init_secret` as SQL/JSON blobs — extractor is a query, not an OpenMLS fork.

**Recommended rung: 1** (full differential PCS as specified). Detail and command transcripts in `docs/issues/010-pcs-oracle-feasibility.md`.

This does **not** accept ADR-0007 and does **not** build the store or the oracle job.

---

## Next (tasked, no deadline) — perf baselines

`test-harness/perf` is owned and empty. After this SPIKE PR:

- Build on-demand throughput/latency baselines against the **live compose stack** for paths that exist today: F2 create/Welcome, F4 send/recv RTT + sustained send, gateway subscribe under concurrency, message fetch at ADR-0005 page limit 500.
- Record environment with every number; commit a baseline file for diffs; fail loud if stack is missing (PLAN §13).
- **Not in scope:** optimization, touching unowned crates, CI gate on every push.

Desktop shell (`grok/m2-desktop-shell` / PR #3 era) remains mock-backed; real-core wiring is M3 and held by the integration checkpoint (advisor status).

---

## Historical

### Desktop shell (M2 mock) — earlier sessions

Mock-backed Tauri 2 + React shell under `apps/desktop/`. Honesty rules: never green "encrypted" on mock data; no direct REST/WS from React; no real citadel-core in that PR.

### Desktop CI job — MERGED (PR #5)

`fb13d9b` on main. Path filter on `apps/desktop/**`.

---

## Carry-forward

1. Worktree only: `citadel-grok`.
2. After charge merges this SPIKE: start `grok/perf-baselines` for `test-harness/perf`.
3. Do not touch `crates/` unless charge reassigns.
4. MSRV **1.95.0**; bumps need ADR.
5. No AI attribution (AGENTS.md rule 13).
6. Real-core desktop wiring is M3, not unparked by the SPIKE.
