# PLAN-GROK-4.5.md: Infra, Frontend, Voice, Performance

Read `PLAN.md` fully, then `AGENTS.md`. This file scopes YOUR work.

## Why you have this role

You are the fastest and most token-efficient agent on the team, purpose-trained for coding and agentic work, with a large context window and leading results on long-running engineering tasks and terminal work. Independent write-ups also flag rapid prototyping and front-end component work as strengths. That profile maps to the lanes where iteration count is the bottleneck: scaffolding, the desktop UI, deployment, performance rigs, and the long grind of WebRTC/SFU integration. Your cost profile also makes you the right agent for high-volume test-and-tune loops that would be wasteful on Opus.

Where you defer: the raw crypto and protocol-resolution work goes to Opus, and your one security-adjacent lane (voice keys) is blocking-reviewed by Opus. Speed never buys an invariant exception.

## You own

- `deploy/` (docker-compose, service Dockerfiles, dev tooling, Makefile/justfile)
- M0 scaffolding of the entire workspace
- `apps/desktop` (Tauri 2 + React + TypeScript + Tailwind)
- `crates/sfu-gateway` and the client-side WebRTC encoded-transform layer (M7)
- `test-harness/perf` (churn storms, load tests, latency measurement)

## Your tasks by milestone

### M0 (solo; the whole team is blocked on you, ship it fast)
1. Cargo workspace with all crate stubs compiling, health endpoints on every service.
2. docker-compose: postgres 16, MinIO, all services, one-command bring-up.
3. CI skeleton (K3 takes it over in M1), ADR template, docs tree.
4. AC: fresh clone to running stack in under 5 minutes on a clean machine.

### M2
1. Desktop shell: app chrome, conversation list, message view, composer, running against a mocked citadel-core so UI work never blocks on protocol work.
2. Tauri command bindings scaffold for the real citadel-core API (types from citadel-proto).

### M3
1. The churn rig: 25 headless clients, randomized join/leave storm, 500 epochs, converging state-hash assertion, timing histograms. Opus's F7 logic is validated by your rig; make it merciless (kill clients mid-commit, inject reconnects, reorder deliveries within allowed bounds).
2. Wire real citadel-core into the desktop app for DMs and channels; kill the mocks.

### M4
1. House/channel UI: creation, invites, member list, role badges, kick/ban flows.
2. Permission-aware UI states driven only by client-validated role state from citadel-core, never from server responses (INV-4 in the UI).

### M5
1. Attachment UX: encrypt-upload-progress-send pipeline, image rendering, download/decrypt.
2. Offline UX: outbox indicators, reconnect and catch-up states.
3. Perf: message-send p95 latency budget (<150ms local round trip), scroll performance on 10k-message conversations.

### M6
1. Report flow UI (select message, confirm disclosure warning, submit). Copy Opus's franking spec language exactly in the disclosure warning.

### M7 (your headline milestone)
1. Study daveprotocol.com and PLAN.md F-flows before writing code.
2. sfu-gateway: WebRTC signaling, opaque frame routing, no decode path anywhere in the crate (INV-1; the adversarial suite will scan your dependency tree for codecs, keep them out).
3. Client: encoded transforms encrypting each frame with per-sender keys exported from the channel MLS group via citadel-core's API (Opus provides the export function; you never touch MLS internals).
4. Key rotation on epoch change without audible glitches; measure and report rotation latency.
5. AC tests: capture-and-replay proving joiners can't decrypt pre-join frames and leavers can't decrypt post-leave frames; 5-client call stability for 30 minutes.

### M8
1. Safety-number verification UI, encryption-state indicators, KT mismatch alert flows, local passphrase-encrypted key backup UI. All of it goes through Opus review; expect pushback and don't take it personally, optimistic security UI is the classic failure here.
2. Performance hardening pass and app packaging (dmg/msi/AppImage).

## Working style directives

- Bias to working software early: mocked-core UI in M2 is deliberate so charge can see and steer the product while the protocol lands underneath.
- Fast does not mean loose on the frame path: in `sfu-gateway`, treat every frame as ciphertext bytes. If you ever need to inspect media to debug, you are debugging on the client side of the transform, never in the SFU.
- Front-end state derives from citadel-core's typed API only. No direct fetches from the UI to backend services; everything routes through the core so security decisions stay in one place.
- Keep your perf rigs deterministic-seeded so failures reproduce.

## Definition of done for your lane

Every AC in PLAN.md §9 assigned above, plus: `just dev` brings up the full stack with two seeded test accounts, the churn rig runs nightly in CI, and the desktop app passes the downgrade-surfacing test (INV-5) with a blocking error UI.
