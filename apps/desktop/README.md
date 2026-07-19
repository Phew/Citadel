# apps/desktop — Citadel desktop shell

**Stack:** Tauri 2 + React + TypeScript + Tailwind  
**Owner:** Grok (see `plans/PLAN-GROK-4.5.md`)  
**Milestone:** M2 prep (shell against **mocked** citadel-core)

## Honest mock boundary

This app is deliberately runnable **before** real citadel-core / M1 services land.

| Claim | Mock behavior |
|-------|----------------|
| Core mode | Always `mock` |
| Backend services | Always `unavailable` (no REST/WS from UI) |
| Session / users | Always none |
| Encryption status | Always `unavailable` — **never** a green “encrypted” claim |
| Default inbox | **Empty** |

Optional **mock fixtures** exist only for layout exercise. Every fixture title contains `[MOCK FIXTURE]`, senders are labeled `[MOCK]`, and message rows carry `isMock: true` + `encryptionStatus: "unavailable"`.

Frontend state flows through `src/lib/core-client.ts` only. Do not add direct fetches to auth/delivery/directory/blobstore from React (PLAN-GROK-4.5).

### Transport selection (M2)

| Runtime | Transport | Implementation |
|---------|-----------|----------------|
| Tauri webview (`pnpm tauri:dev`) | `tauri-invoke` | `invoke` → Rust mock commands in `src-tauri` |
| Browser (`pnpm dev`) | `in-process-mock` | TypeScript mock in `src/mock/` |

Both paths are **mock** (mode/backend/session/encryption honesty identical). Footer shows `transport=…`.

## Layout

```
apps/desktop/
  src/                     # React UI
    mock/                  # In-process mock (browser) + vitest
    lib/core-client.ts     # Transport boundary (isTauri → invoke | TS mock)
    lib/tauri-core-client.ts  # invoke wrappers + wire mapping
    components/            # chrome, list, messages, composer
  src-tauri/               # Tauri host + command scaffold
    src/mock.rs            # Rust-side mock store (same honesty rules)
    src/commands.rs        # core_get_status, core_list_*, core_send_mock_local, …
  package.json
```

`src-tauri` is **not** a workspace member of the root Cargo workspace so service CI does not need WebView2. Build it via pnpm/tauri from this directory.

## Prerequisites

- Node 20+ / pnpm
- Rust toolchain matching repo `rust-toolchain.toml` (1.95.0)
- Windows: WebView2 runtime (usually present on Win10/11)
- `cargo install tauri-cli` (or use `pnpm tauri` which uses the local CLI)

## Commands

```bash
cd apps/desktop
pnpm install

# Frontend only (browser) — mock UI without native shell
pnpm dev

# Unit tests (mock honesty + empty defaults)
pnpm test

# Typecheck + production bundle (CI also runs this)
pnpm build

# Full Tauri window (native)
pnpm tauri:dev

# Rust mock store tests (CI also runs this under src-tauri)
cd src-tauri && cargo test --locked
```

## CI

Path-filtered job on `main` (`.github/workflows/ci.yml`): changes under
`apps/desktop/**` run `pnpm install --frozen-lockfile`, `pnpm test`,
`pnpm build`, and `cargo test --locked` in `src-tauri`. Rust-only pushes skip
the job.

## M2 scope (Grok slice)

- [x] App chrome, conversation list, message view, composer
- [x] Mocked citadel-core with clear labeling
- [x] Tauri command scaffold for real core later
- [x] React → Tauri `invoke` when inside webview (still mock-backed)
- [ ] Merge to main only after M1 multi-client harness checkpoint (charge)

## M3 handoff

1. Keep `getCitadelCore()` / invoke names; replace Rust mock bodies with citadel-core.
2. Delete or gate mock fixtures behind a dev-only flag.
3. Encryption / session UI must then reflect **core-reported** status only (INV-4, INV-5).
4. `core_send_message` becomes the real path; drop or hard-gate `core_send_mock_local`.

## Invariants touched (UI)

- **INV-4:** UI does not trust server assertions; mock exposes no server-derived role/membership claims.
- **INV-5:** No silent unencrypted fallback UI; mock never claims encryption success.
