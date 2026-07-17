# apps/desktop

Tauri 2 + React + TypeScript + Tailwind desktop client.

Scaffolded empty in M0. Real shell (mocked citadel-core) lands in **M2** under
Grok ownership. All UI security state must come from citadel-core's typed API —
never direct backend fetches from the UI (PLAN-GROK-4.5.md).
