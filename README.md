# Citadel

Working name: **Citadel** (`citadel-app`). A Discord-style community chat platform
with Signal-level end-to-end encryption. The server is an untrusted router and
blob store — it must never read message content, voice, or video.

> **Agents:** read `plans/PLAN.md`, then `plans/AGENTS.md`, then your role plan
> under `plans/PLAN-*.md` before writing code.

## Security (summary)

Ten hard invariants live in `plans/PLAN.md` §2. Highlights:

- **INV-1:** No plaintext server-side
- **INV-2:** Keys never leave the client
- **INV-5:** No silent downgrade to unencrypted
- **INV-10:** No crypto primitives from scratch (OpenMLS only)

## M0 quick start

**Prerequisites:** Rust (see `rust-toolchain.toml`), Docker Compose v2, [just](https://github.com/casey/just) (optional).

```bash
# Toolchain + unit tests
just setup
just check

# Full local stack (postgres, minio, four service stubs)
just dev
```

Service health:

```text
GET http://127.0.0.1:8081/health   # auth-service
GET http://127.0.0.1:8082/health   # delivery-service
GET http://127.0.0.1:8083/health   # directory-service
GET http://127.0.0.1:8084/health   # blobstore-service
```

Fresh clone → green unit tests is `cargo test --workspace`. Fresh clone →
running stack is `just dev` (target: under five minutes on a clean machine).

## Repository layout

```text
crates/
  citadel-proto/       shared envelopes + error taxonomy
  citadel-core/        client core (plaintext boundary)
  auth-service/        accounts, devices, KT (M1+)
  delivery-service/    MLS DS + fanout (M2+)
  directory-service/   houses / channels (M4+)
  blobstore-service/   encrypted attachments (M5+)
  kt-log/              key transparency lib (M1+)
  test-harness/        multi-client + wait-healthy
apps/desktop/          Tauri + React (M2+)
deploy/                docker-compose, Dockerfiles
docs/decisions/        ADRs
docs/protocol/         flow specs
plans/                 architecture + agent process
```

## CI

GitHub Actions (`.github/workflows/ci.yml`):

1. `cargo fmt` / `clippy -D warnings` / `test`
2. `cargo audit` + `cargo deny`
3. `docker compose` smoke: all service `/health` endpoints

## Team

See `plans/AGENTS.md`. Branches: `opus/<task>`, `k3/<task>`, `grok/<task>`.
One worktree per agent; merges to `main` require charge.
