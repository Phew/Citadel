# 003: auth-service endpoints blocked on missing docs/protocol/auth.md

- **Reporter:** k3
- **Date:** 2026-07-16 (renumbered from 001 → 003 on 2026-07-17; Opus holds 001/002)
- **Blocks:** M1 / k3 (auth-service endpoints, token issuance)
- **Related:** plans/PLAN.md §7 F1, §8; plans/PLAN-KIMI-K3.md M1 task 1; AGENTS.md rules 3, 8; docs/decisions/0002

## Problem

My kickoff scopes auth-service "exactly per docs/protocol/auth.md and the
citadel-proto payload builders." The spec doc still does not exist
(docs/protocol/ on both `main` and `origin/opus/m1-proto` is the M0 scaffold
README only).

**Resolved since first filing:** Opus has now pushed `origin/opus/m1-proto`:
citadel-proto auth/credential/kt contracts (d11dfcb), the
citadel-service-crypto facade (25a79c4), kt-log with ADR-0001 (e8e29d1), and
ADR-0002 for the facade (d700149). Those unblock the contract side once
merged to main. What remains missing is the flow spec pinning operational
parameters I must not improvise (scope rule 3):

- challenge TTL and single-use semantics; token TTL, storage model
  (server-side session table? stateless?), and revocation behavior on device
  revoke;
- pool target size enforcement (F1 step 4 says N=100 — is that a minimum
  the server enforces, a client convention, or advisory?);
- rate-limit posture for auth endpoints (M8 assigns rate limiting to me;
  M1 needs at least a documented stance for challenge issuance);
- KT endpoint details: does `GET /v1/kt/proof` take leaf index or leaf hash,
  and against which tree size (latest only, or arbitrary historical STHs)?

## What I need from charge

1. A decision on `docs/protocol/auth.md`: either Opus/charge publishes it,
   or a ruling that the citadel-proto `auth`/`kt` modules plus this list are
   the canonical spec, in which case I will draft the operational parameters
   above as a PROPOSED ADR for charge to accept (not improvise them).
2. Merge of `opus/m1-proto` to main (after ADR review, see docs/issues/004)
   so I can build against the contracts on main.

## Non-goals / what I will not improvise

- No token format/TTL, challenge parameters, or validation rules of my own
  design. No hand-concatenated signing payloads (proto builders only).
- No direct crypto dependencies in auth-service — citadel-service-crypto
  only, per ADR-0002 and rule 6.

## Status of my other M1 work (not blocked)

Delivered and pushed: CI hardening (k3/m1-ci-hardening), harness framework
(k3/m1-harness-framework), canary scan (k3/m1-canary-scan), KeyPackage pool
with real-PG16 concurrency property test + db-tests CI job
(k3/m1-keypackage-pool). Opus's issue 002 (deny.toml crypto bans) is
accepted into my lane; implementation lands once the wrapper crates exist on
main. Opus's issue 001 (Go oracle import, option A suggests I CI-wire it)
awaits charge's decision.
