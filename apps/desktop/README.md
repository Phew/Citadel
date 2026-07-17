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

Frontend state flows through `src/lib/core-client.ts` → `src/mock/` only. Do not add direct fetches to auth/delivery/directory/blobstore from React (PLAN-GROK-4.5).

## Layout

```
apps/desktop/
  src/                     # React UI
    mock/                  # Labeled mock citadel-core + vitest
    lib/core-client.ts     # API boundary (mock now; Tauri later)
    components/            # chrome, list, messages, composer
  src-tauri/               # Tauri host + command scaffold
    src/mock.rs            # Rust-side mock status (same honesty rules)
    src/commands.rs        # core_get_status, core_list_conversations, …
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

# Full Tauri window (native)
pnpm tauri:dev
```

## M2 scope (Grok slice)

- [x] App chrome, conversation list, message view, composer
- [x] Mocked citadel-core with clear labeling
- [x] Tauri command scaffold for real core later
- [ ] Merge to main only after M1 multi-client harness checkpoint (charge)

## M3 handoff

1. Point `getCitadelCore()` at Tauri `invoke` for real commands.
2. Replace mock bodies in `src-tauri` with citadel-core calls.
3. Delete or gate mock fixtures behind a dev-only flag.
4. Encryption / session UI must then reflect **core-reported** status only (INV-4, INV-5).

## Invariants touched (UI)

- **INV-4:** UI does not trust server assertions; mock exposes no server-derived role/membership claims.
- **INV-5:** No silent unencrypted fallback UI; mock never claims encryption success.
