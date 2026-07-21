# Grok status handoff

**Agent:** Grok (Grok 4.5)  
**Updated:** 2026-07-20 (M1 closed; M2 open — shell PR #3 rebased and unparked)  
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

**Process hard rules:** AGENTS.md especially (1) own worktree only, (2) commit early, (8) escalate don’t improvise, (10) PR descriptions state milestone / invariants / named tests, (13) **no AI attribution signatures**. Charge alone merges to `main` and accepts ADRs. **CI workflow changes do not self-merge.**

---

## Current work — M2 desktop shell (PR #3), unparked

| Item | Value |
|------|--------|
| Branch | `grok/m2-desktop-shell` |
| Base | `origin/main` @ `08070d4` (M1 closed; README M2 next) |
| PR | https://github.com/Phew/Citadel/pull/3 |
| Scope | `apps/desktop/**` + `docs/status/grok.md` only — **no `crates/`** |
| Mode | Mock-backed shell; real citadel-core wiring is a **follow-up PR** (waits on Opus Task 2 / DM core) |
| Merge | Charge merges; shell is mock-only and invariant-surface-free — eligible on its own once green |

### What the shell is

1. Tauri 2 + React + TypeScript + Tailwind under `apps/desktop/`.
2. Honest mock defaults: empty inbox, `backend=unavailable`, `session=null`, `encryptionStatus=unavailable`.
3. Persistent non-dismissible mock banner + footer transport label.
4. Transport: webview → `tauri-invoke` (Rust mock); browser → `in-process-mock` (TS mock).
5. Command scaffold: `core_get_status`, `core_list_*`, `core_send_mock_local`, fixtures; `core_send_message` hard-rejects.
6. Standalone `[workspace]` in `src-tauri` (not root workspace).
7. Empty/whitespace mock-send rejection tests (Rust + vitest).

### Local verify (this session)

```text
pnpm test   → 13 passed
pnpm build  → ok
cargo test --locked (src-tauri) → 6 passed
```

### Honesty rules (do not regress)

- Never green “encrypted” / verified-user chrome on mock data.
- Never imply backend availability.
- Never invent real accounts; fixtures stay labeled.
- No direct REST/WS from React to services.
- Do not wire real citadel-core in this PR.

### How to run

```bash
cd apps/desktop
pnpm install
pnpm test
pnpm build
pnpm dev               # browser → in-process-mock
pnpm tauri:dev         # webview → tauri-invoke (still mock)
cd src-tauri && cargo test --locked
```

---

## Historical

### Desktop CI job — MERGED (PR #5)

| Item | Value |
|------|--------|
| PR | https://github.com/Phew/Citadel/pull/5 |
| Merge | `fb13d9b` on main |
| Final form | path filter + `rustc --version` + pnpm install/test/build + cargo test in `src-tauri` |
| Execution proof on shell path | run **29704933798** (day 4; desktop job 88240219215) |

### Day 4 (parked era)

Rebased onto main @ `33d775a`, empty-body tests, desktop job execution proof, then parked pending M1 checkpoint. Superseded by this unpark.

---

## Carry-forward for next Grok session

1. Confirm worktree: `git rev-parse --show-toplevel` → must be `citadel-grok`.
2. After charge merges PR #3: wait for Opus DM core (Task 2) before a **follow-up** PR that swaps mock command bodies to real citadel-core.
3. Do not touch `crates/` from the desktop shell lane unless charge reassigns.
4. Desktop CI contract: path filter on `apps/desktop/**` must stay green.
5. MSRV **1.95.0**; bumps need ADR.
6. No AI attribution (AGENTS.md rule 13).
