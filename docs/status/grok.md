# Grok status handoff

**Agent:** Grok (Grok 4.5)  
**Updated:** 2026-07-17  
**Audience:** a fresh Grok instance with **zero** memory of prior sessions. Read this, then `plans/PLAN.md`, `plans/AGENTS.md`, `plans/PLAN-GROK-4.5.md`.

---

## Who you are

You are Grok on the Citadel team (E2E encrypted Discord-style chat). Your owned lanes:

| Area | Path / scope |
|------|----------------|
| Infra / scaffolding | M0 (done); ongoing `deploy/` |
| Desktop | `apps/desktop` (Tauri 2 + React + TS + Tailwind) |
| Voice | `crates/sfu-gateway` + client encoded transforms (**M7**) |
| Perf | `test-harness/perf` |

**Branch prefix:** `grok/<task>`  
**Worktree:** one dedicated worktree only. Primary checkout (`…/citadel/citadel` or `…/Citadel/Citadel`) belongs to **charge**. Sibling worktree used previously: `…/citadel/citadel-grok`. Do not edit primary.

**Process hard rules:** AGENTS.md especially (1) own worktree only, (2) commit early, (8) escalate don’t improvise, (10) PR descriptions state milestone / invariants / named tests. Charge alone merges to `main` and accepts ADRs.

---

## M0 final state (merged)

| Item | Value |
|------|--------|
| PR | https://github.com/Phew/Citadel/pull/1 |
| Merge commit on `main` | `14bafbe` (*Merge pull request #1 from Phew/grok/m0-scaffolding*) |
| Feature tip (pre-merge) | `ac00099` |
| Remote | `origin` → `https://github.com/Phew/Citadel.git` |
| Feature branch | `grok/m0-scaffolding` was pushed then deleted after merge (normal) |

### What M0 delivered

- **Pinned toolchain:** `rust-toolchain.toml` → **1.95.0** (+ rustfmt, clippy). `Cargo.toml` `rust-version = "1.95.0"`. Do not bump without ADR (PLAN §13).
- **Workspace crates:** `citadel-proto`, `citadel-core`, `auth-service`, `delivery-service`, `directory-service`, `blobstore-service`, `kt-log`, `test-harness`.
- **`citadel-proto`:** JSON wire envelopes (`Envelope`, `EnvelopeKind`, base64 payload), `ErrorCode` / `ErrorResponse` taxonomy, typed IDs. This crate is canonical for wire contracts (AGENTS rule 5).
- **Service stubs:** each binary exposes `GET /health` and `GET /ready` on ports **8081–8084**.
- **Deploy:** `deploy/docker-compose.yml` — Postgres 16, MinIO (+ bucket init), four services. Shared image build: `deploy/docker/Dockerfile.service` (`SERVICE` build-arg, `--locked`).
- **Dev UX:** root `justfile` (`just check`, `just dev`, `wait-healthy` via `test-harness` bin).
- **CI:** `.github/workflows/ci.yml` — fmt, clippy `-D warnings`, test; cargo-audit + cargo-deny; compose smoke after rust job.
- **Docs scaffold:** `docs/decisions/` (ADR template `0000-template.md`), `docs/protocol/`, `docs/issues/`.
- **Desktop:** only `apps/desktop/README.md` placeholder (real shell is **M2**).

### M0 acceptance (how to re-verify)

```bash
git checkout main   # or a worktree on origin/main
just check          # fmt-check + clippy -D warnings + cargo test --workspace
just dev            # compose up --build + wait-healthy (timeout 120s)
curl -s http://127.0.0.1:8081/health   # auth
curl -s http://127.0.0.1:8082/health   # delivery
curl -s http://127.0.0.1:8083/health   # directory
curl -s http://127.0.0.1:8084/health   # blobstore
```

---

## Carry-forward notes (scaffolding lessons)

1. **Repo layout on disk (Windows):** container folder `Documents/github/citadel/` is **not** a git repo. Primary is nested `…/citadel/citadel` (case-insensitive alias `…/GitHub/Citadel/Citadel`). Grok worktree is a **sibling**: `…/citadel/citadel-grok`. Diagnose with `git rev-parse --show-toplevel` and `git worktree list` if confused.

2. **Initial toolchain pin:** 1.85.0 was too low for current crates.io transitive MSRV (e.g. `icu_*` / `idna_adapter` need ≥1.86). First pin is **1.95.0**, matching the environment that built M0. Further MSRV changes need an ADR.

3. **`cargo deny`:** allow list must include **`CDLA-Permissive-2.0`** (via `webpki-roots` → reqwest/rustls in `test-harness`). Multiple `getrandom` / `windows-sys` versions warn only (`multiple-versions = "warn"`).

4. **Docker builds:** copy `Cargo.lock` and build with `--locked`. Service images install `curl` for compose healthchecks. MinIO health uses `http://localhost:9000/minio/health/live` (not `mc ready local` without alias setup).

5. **PowerShell + cargo:** piping `cargo … 2>&1` can surface as a non-zero exit even when tests pass (NativeCommandError on stderr). Prefer `$LASTEXITCODE` after bare `cargo` invocations.

6. **No `origin` at kickoff:** remote was added later as `https://github.com/Phew/Citadel.git`. Do **not** push to `citadel-app/citadel` (unrelated public product) or `Phew/Epoch` (predecessor; PLAN is clean-slate).

7. **`main` is locked by charge’s primary worktree.** In the Grok worktree, create branches with `git checkout -B grok/<task> origin/main` instead of checking out `main` directly.

8. **Team sequencing:** M0 was Grok solo. After merge, other agents start M1 (Opus: proto/crypto/kt; K3: auth, harness, CI hardening, canary). **Your next code milestone is M2**, not M1.

9. **Crypto confinement (later):** services must not grow OpenMLS/custom crypto. Opus owns `citadel-service-crypto` facade (AGENTS rule 6). You never improvise crypto for UI or SFU key paths; Opus blocking-reviews SFU frame path in M7.

10. **UI security model (M2+):** desktop state comes **only** from citadel-core’s typed API (Tauri commands). No direct REST/WS from React to backend services (PLAN-GROK-4.5).

---

## Next assignment: M2 desktop shell (when M2 opens)

**Do not start M2 until the multi-client harness integration checkpoint after M1 is green** (AGENTS sequencing + milestone checkpoint). When charge/session says M2 is open:

### Goal

Ship a usable desktop shell so charge can see and steer product while protocol lands underneath.

### Scope (from PLAN-GROK-4.5 / PLAN.md §9 M2)

1. **App chrome:** window shell, navigation, conversation list, message view, composer.
2. **Mocked citadel-core:** UI must run against mocks so you never block on OpenMLS/F2/F4. Prefer a clear mock boundary that can be swapped for real Tauri commands later (M3 wires real core).
3. **Tauri 2 command scaffold:** typed bindings aligned with `citadel-proto` types; stubs or mocks behind the same API surface the real core will implement.
4. **Stack:** Tauri 2 + React + TypeScript + Tailwind under `apps/desktop/`.

### Non-goals for M2 (yours)

- Real MLS encrypt/decrypt (Opus / citadel-core).
- Real delivery-service / WS integration from the UI (goes through core later).
- SFU / voice (M7).
- Franking / reports UI (M6).

### Suggested branch / process

- Worktree: your own only; branch `grok/m2-desktop-shell` (or similar) off current `origin/main`.
- Commit early; PR description per AGENTS rule 10 (milestone M2, invariants INV-4/INV-5 UI implications if any, named tests or manual repro steps).
- Self-merge **only** pure frontend if CI green; anything touching core/proto/security-state UI routes to Opus review.

### Definition of done (M2 Grok slice)

- Desktop app launches locally.
- Conversation list + message view + composer work against mocks.
- Tauri command surface sketched for real core.
- No silent unencrypted path in UI (INV-5: if you surface connection/encryption state, never imply plaintext fallback).

---

## Quick start for next session

```text
1. Read plans/PLAN.md, plans/AGENTS.md, plans/PLAN-GROK-4.5.md
2. git fetch origin
3. Ensure you are in YOUR worktree (not charge primary)
4. git checkout -B grok/<task> origin/main
5. Confirm M1/harness checkpoint before starting M2 code
6. If anything is ambiguous: docs/issues/NNN-*.md or PROPOSED ADR — escalate, don’t improvise
```

**Stop condition for this handoff file’s author:** M0 closed; status pushed; no further work tonight.
