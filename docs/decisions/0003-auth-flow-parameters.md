# ADR-0003: Auth-flow operational parameters (challenge-response, tokens, pool, KT proof endpoint)

- **Status:** PROPOSED
- **Date:** 2026-07-17 (rev 2: 2026-07-19 — folds Opus's blocking review,
  docs/issues/005, findings A/B/C; still PROPOSED — charge marks ACCEPTED)
- **Deciders:** charge (required for ACCEPTED); author: K3. Blocking review: Opus (auth flows are Opus's review surface).
- **Invariants touched:** INV-2 (token/key handling), INV-9 (challenge + token randomness)
- **Related:** plans/PLAN.md §7 F1, §8; docs/issues/003; docs/issues/004 (F1, F4); docs/issues/005 (Opus review); docs/decisions/0001, 0002; crates/citadel-proto/src/auth.rs

## Context

citadel-proto pins the auth wire contracts (request/response shapes,
signing inputs), but the operational parameters of the F1 auth flow exist
nowhere (docs/issues/003). Until they are decided, auth-service endpoints
cannot be implemented without improvising (scope rule 3). This ADR proposes
the smallest parameter set that implements PLAN.md §8's "bearer tokens from
device-key challenge-response" with no new mechanisms. It deliberately
specifies nothing already owned by citadel-proto (rule 5); where a choice
implies a proto shape change, it is marked as a proposal to Opus.

## Decision

1. **Challenge.** 32 bytes from the OS CSPRNG via
   `citadel-service-crypto::random_array` (INV-9). Single-use, TTL 120 s.
   Stored server-side (`auth_challenges(device_id, challenge, expires_at)`);
   at most one outstanding challenge per device — a new request replaces
   the old (natural anti-amplification). Any verify attempt consumes the
   challenge, success or failure (anti-replay); an expired or missing
   challenge is `unauthorized`.
2. **Token.** Opaque bearer: 32 bytes from the OS CSPRNG via
   `citadel-service-crypto::random_array` — the same facade random
   capability as (1)'s challenge (INV-9 / rule 6: a bearer credential is
   never generated with `rand::thread_rng` or a bare `getrandom` call
   bypassing the facade) — base64url (no-pad) on the wire. Stored
   server-side as `SHA-256(token)` (facade
   sha256) in `auth_tokens(token_hash, device_id, issued_at, expires_at,
   revoked_at)` — a database leak discloses no usable token. TTL 24 h.
   Renewal is a fresh challenge-response; no refresh-token mechanism in v1.
3. **Revocation.** Token validation joins `devices`: a token is valid iff
   unexpired, not revoked, and its device has `revoked_at IS NULL`.
   Revoking a device therefore kills its tokens immediately. Account-level
   suspension cascades through the same mechanism: suspending an account
   sets `revoked_at` on all of that account's devices (one audited
   administrative write), so its tokens die on the same immediate
   semantics — test `account_suspension_revokes_all_device_tokens`.
   Rationale: revocation state lives in exactly one column and the
   per-request validation path is unchanged; a second
   `accounts.status = 'active'` join on the hot path could only drift from
   the first. Validation is
   a per-request indexed lookup; v1 scale needs no cache (a cache would
   reopen the revocation-latency question — revisit in M8).
4. **KeyPackage pool policy.** Publish accepts at most 100 packages per
   request (F1's N=100 batch size; bounds request body size). The server
   enforces no minimum and no total cap: pool level is client-observable
   (`pool_size` in the publish response) and replenishment is the client's
   duty. Consuming fetch is all-or-nothing across the account's active
   devices (implemented in the M1 pool store; empty pool for any active
   device → `key_package_unavailable`, nothing burned).
5. **KT proof endpoint.** `GET /v1/kt/proof?leaf=<index>[&tree_size=<n>]`
   returns the `InclusionProof` **and** the `SignedTreeHead` it verifies
   against as one atomic response (default `tree_size` = latest STH).
   Rationale: proof and head must match exactly (kt-log rejects mismatches);
   returning them together removes a TOCTOU race where the log grows
   between two client calls. This adds a response wrapper type to
   citadel-proto's `kt` module — proposal to Opus as sole proto merger;
   the endpoint path and verb are unchanged from PLAN.md §8.
6. **Registration is unauthenticated** (no prior credential exists) and is
   the only unauthenticated write besides challenge issuance. Handle
   validation: 1–64 bytes of UTF-8; **no uniqueness enforcement** —
   identity is `account_id` bound in the KT log; handles are display
   metadata (the Signal model; uniqueness would also create an enumeration
   oracle). The 64-byte cap also keeps `KtLeaf::leaf_bytes()` far from its
   u16-prefix wrap (docs/issues/004 F3).
7. **M1 rate-limit stance:** none beyond (1)'s one-outstanding-challenge
   rule and (4)'s batch cap. Real rate limiting is M8 (K3 lane) and will be
   designed against the threat model then; no half-measures now.
   **Accepted M1 risk (accepted by charge, 2026-07-19):** unauthenticated
   registration (6) is an unbounded, *permanent* append to the insert-only
   KT log — each registration adds a leaf that can never be pruned without
   breaking the consistency proofs clients depend on (ADR-0001 §4), and it
   taxes every future startup rebuild (O(n), ADR-0001 §4). That is a
   sharper asymmetric-cost DoS than generic API abuse, and it is
   consciously ACCEPTED for M1 rather than omitted: the risk is recorded
   here, deferred to M8, with bounded M8 options noted — per-source
   registration caps and/or a small registration proof-of-work, designed
   against the threat model with the rest of M8 rate limiting.

## Alternatives considered

1. **Stateless signed tokens (JWT-style)** — no session table, but
   revocation-on-device-revoke becomes impossible without a blocklist
   (which is a session table by another name). Server-side tokens are
   simpler and honestly revocable.
2. **Long-lived tokens / refresh tokens** — fewer challenge round-trips,
   more machinery and more stolen-token window. Challenge-response over a
   locally-held device key is cheap; 24 h is the boring choice.
3. **Server-enforced pool minimum/top-up** — pushes client policy into the
   server for no security gain; the client already sees `pool_size`.
4. **Unique handles** — familiar, but adds an enumeration oracle and solves
   nothing the KT binding doesn't (F1 trust runs through `account_id` +
   verified credentials, INV-4).

## Consequences

- Positive: every parameter above is implementable against
  citadel-service-crypto's three capabilities; no new tables beyond
  `auth_challenges` and `auth_tokens`; token theft via DB read is
  neutralized (hash-only storage); revocation semantics are immediate and
  testable.
- Negative: per-request token lookups (fine at v1 scale); no device-token
  sharing (each device authenticates itself — intended); 24 h re-auth is
  user-visible only as a background challenge-response.
- Follow-ups: docs/issues/003 closes on acceptance; M8 rate limiting
  revisits (7); Opus proto PR adds the KT proof+head wrapper (5) — landed
  on main via PR #7.

## Evidence

Named tests that will prove compliance (auth-service PR, Opus
blocking-review; all against real PostgreSQL 16 in the CI db-tests job):

- `auth_challenge_single_use_and_expiry` — replay of a consumed/expired
  challenge rejected; new challenge replaces outstanding one.
- `auth_token_hashed_at_rest` — token column contains no token bytes
  (scan-style assertion over `auth_tokens`).
- `device_revocation_invalidates_tokens_immediately`
- `account_suspension_revokes_all_device_tokens` — suspension cascades to
  `devices.revoked_at` for every device of the account; its tokens are
  rejected immediately after (3).
- `publish_rejects_oversized_batch`; `pool_exhaustion_is_all_or_nothing`
  (already landed: `account_fetch_is_all_or_nothing`, CI db-tests).
- `kt_proof_response_pairs_proof_and_head` — mismatched pair impossible by
  construction.
- `registration_rejects_long_handles` — 65-byte handle → `invalid_request`.
