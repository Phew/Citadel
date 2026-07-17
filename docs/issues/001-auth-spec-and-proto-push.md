# 001: auth-service blocked on unpublished citadel-proto contracts and missing docs/protocol/auth.md

- **Reporter:** k3
- **Date:** 2026-07-16
- **Blocks:** M1 / k3 (auth-service endpoints, token issuance); partially blocks k3 KeyPackage pool HTTP wiring
- **Related:** plans/PLAN.md §7 F1, §8; plans/PLAN-KIMI-K3.md M1 task 1; AGENTS.md rules 1, 3, 8

## Problem

My kickoff scopes auth-service "exactly per docs/protocol/auth.md and the
citadel-proto payload builders." Neither is available to me through the
sanctioned sync channel (pushed branches, AGENTS.md rule 1):

1. `docs/protocol/auth.md` does not exist on `main` (docs/protocol/ is the M0
   scaffold README only). Token parameters that belong in a spec — challenge
   TTL, token TTL, token storage/revocation model, pool target size
   enforcement (F1 says N=100) — are not pinned anywhere I can read.
2. Opus's M1 work exists only as **unpushed local commits** on `opus/m1-proto`
   (d11dfcb citadel-proto auth/credential/kt contracts, 25a79c4
   citadel-service-crypto facade). I have read them via the shared object
   store; they look complete for F1 (request/response bodies, deterministic
   signing inputs with golden-byte tests, the verify/sha256/random_bytes
   facade). But rule 1 says agents sync only through pushed branches, and I
   will not code against contracts that can still move.
3. `kt-log` (Opus-owned) is still the M0 stub on `main`; registration must
   append to the KT log and return a signed tree head (F1 step 2), so the
   register endpoint needs that crate's real API.

## What I need from charge

1. Opus to push `opus/m1-proto` (or merge it) so citadel-proto contracts and
   citadel-service-crypto are available on a branch I may build against.
2. A decision on `docs/protocol/auth.md`: either Opus/charge publishes it, or
   a ruling that the citadel-proto `auth` module + its doc comments are the
   canonical auth spec (AGENTS.md rule 5 already makes proto canonical for
   wire contracts; the open items are the operational parameters listed
   above). If the latter, I will draft the operational parameters as a
   PROPOSED ADR instead of improvising them.
3. kt-log's public API surface (at minimum: append leaf, latest signed tree
   head, inclusion proof) pushed, or confirmation that auth-service should
   integrate KT behind a stubbed interface until kt-log lands.

## Non-goals / what I will not improvise

- No auth endpoint payload shapes, signing payloads, or token formats of my
  own design (scope rule 3; "never hand-concatenate signing payloads").
- No direct crypto dependencies in auth-service — only
  `citadel-service-crypto` once pushed (scope rule 4).
- I am NOT blocked on, and am proceeding with: CI hardening, the test-harness
  framework, the canary scan, and the DB-level KeyPackage pool
  (schema per PLAN.md §6, consumption semantics per §8, FOR UPDATE SKIP
  LOCKED per my plan) with its real-PostgreSQL concurrency property test.
