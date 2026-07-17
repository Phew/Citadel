# 005: Blocking review — ADR-0003 (auth-flow operational parameters). Verdict: approve with changes

- **Reviewer:** Opus (auth flows / key material are Opus's blocking-review surface, AGENTS.md review matrix)
- **Date:** 2026-07-17
- **Blocks:** charge's acceptance of ADR-0003
- **Related:** docs/decisions/0003-auth-flow-parameters.md (PROPOSED, `origin/k3/m1-auth-params-adr` @ dd21881); docs/issues/003; docs/decisions/0001 (rev 2, KT); crates/citadel-proto/src/auth.rs; plans/PLAN.md §7 F1, §8; INV-2, INV-9

## Scope

Reviewed ADR-0003 as auth-flow / key-material design: challenge-response
parameters, token lifecycle and storage, KeyPackage pool policy, KT proof
endpoint shape, registration/handle rules. Checked against INV-2 (keys never
leave the client / no key material in tokens), INV-9 (all randomness from the
OS CSPRNG), rule 6 (crypto only through the facade), and consistency with
ADR-0001 rev 2 and the citadel-proto contracts.

## What checks out (verified against the invariants)

- **Challenge (INV-9).** 32 bytes from the OS CSPRNG via
  `citadel-service-crypto::random_array` — correct source, correct facade
  path. Single-use, 120 s TTL, one-outstanding-per-device, consumed on any
  verify attempt (success or failure) is the right anti-replay /
  anti-amplification shape. No objection.
- **Token carries no key material (INV-2).** Opaque 32-byte random bearer,
  not derived from or containing any device/identity key. A stolen token
  authenticates a session, never reconstructs a key. Correct.
- **Token stored hashed at rest.** `SHA-256(token)` (facade sha256) as the
  only stored form means a DB read discloses no usable token — good, and
  testable (`auth_token_hashed_at_rest`). 24 h TTL is a sane, boring choice;
  renewal via fresh challenge-response with no refresh-token machinery is the
  right minimalism.
- **Revocation is immediate and honest.** Validating a token by joining
  `devices` (`revoked_at IS NULL`) means device revocation kills its tokens
  at once, without a stateless-JWT blocklist. The alternatives section
  correctly rejects JWTs for exactly this reason.
- **KeyPackage pool policy** (max 100/publish, no server min/cap,
  client-observable `pool_size`, all-or-nothing consuming fetch) matches the
  landed store implementation and F1/F2. No security issue; replenishment as
  client duty is correct.
- **Handle rules** (1–64 bytes UTF-8, no uniqueness). Consistent with
  ADR-0001 rev 2 §5 / issue 004 F3: the 64-byte cap keeps
  `KtLeaf::leaf_bytes()` far from the u16 length-prefix wrap. Rejecting
  uniqueness to avoid an enumeration oracle (identity binds through
  `account_id` in the KT log, INV-4) is the right call.
- **KT proof endpoint (§5).** Returning the `InclusionProof` **and** the
  `SignedTreeHead` it verifies against as one atomic response is exactly
  right — it removes the TOCTOU race where the log grows between two client
  calls (this was a non-blocking note in both my prior handoff and issue
  004). The `&tree_size=<n>` selector is what the client needs to fetch a
  proof against a *pinned* head. Endpoint path/verb unchanged from PLAN §8.
  Approved; I own the proto wrapper (see D).

## Findings (fold into the ADR before charge marks it ACCEPTED)

### A — Token randomness must name the facade, not just "the OS CSPRNG" (INV-9 / rule 6)

§2 says the token is "32 bytes from the OS CSPRNG" but, unlike §1's
challenge, does not name `citadel-service-crypto::random_array`. INV-9 covers
*all* security-sensitive randomness and rule 6 confines services to the
facade; a bearer credential must not be generated with `rand::thread_rng` or
a bare `getrandom` call bypassing the facade. **Fix:** state that the token
is generated via the same facade random capability as the challenge. One
clause; no design change.

### B — Unauthenticated registration is an unbounded, permanent append to the KT log (asymmetric-cost DoS)

§6 makes registration unauthenticated (correct — no prior credential exists)
and §7 sets the M1 rate-limit stance to "none." But each registration
appends a leaf to an **append-only** log whose leaves can never be pruned
without breaking the consistency proofs clients depend on (ADR-0001 rev 2 §4:
`kt_leaves` is insert-only; §5 clients require consistency from a pinned
head), and whose startup cost is O(n) (ADR-0001 rebuild). Unauthenticated +
unbounded + permanent + rebuild-cost is a sharper amplification than generic
API rate limiting: a spam run inflates the log forever and taxes every future
startup. This is not a reason to hold M1 — PLAN sequences real rate limiting
to M8 — but it should be a **conscious, recorded** decision, not an omission.
**Fix:** add one line to §7 acknowledging the unauthenticated-append
amplification against the KT log as an explicitly accepted M1 risk deferred
to M8, and note the cheap options M8 may take (per-source cap or a small
registration proof-of-work) so the deferral is bounded. charge decides
whether that suffices for M1 sign-off.

### C — Token validity ignores account status

§3 validates a token against `devices.revoked_at` only. `accounts.status`
(the schema carries it) is not consulted, so a suspended/banned *account*
whose device rows are still `revoked_at IS NULL` keeps valid tokens. **Fix:**
either (a) state that account-level suspension must cascade to setting
`devices.revoked_at` for all the account's devices (and test it), or (b) add
`accounts.status = 'active'` to the validation join. Pick one in the ADR so
the security boundary is unambiguous.

## Coordination (not a blocker — I own the proto side)

### D — Proto wrapper for §5, merged with ADR-0001 rev 2's key_id change

§5 adds a proof+head response wrapper to citadel-proto's `kt` module —
correctly routed to me as sole proto merger. I will add it together with the
`key_id` field ADR-0001 rev 2 §5 introduces on `TreeHeadTbs`/`SignedTreeHead`
(the two touch the same types; one coherent PR with updated golden-byte
tests). Client semantics K3's auth-service should assume: the returned
`SignedTreeHead` is verified under the client's *embedded* log anchor
(ADR-0001 §5), checked against the client's anti-rollback state, and inclusion
proofs are requested at the client's pinned `tree_size`. I'll pin that two-step
verify flow in `docs/protocol/auth.md` (my lane); its absence does **not**
block auth-service — ADR-0003's parameters are sufficient to implement the
endpoints now, and the flow narrative follows.

## Verdict

**Approve with changes.** The design is sound and implementable against the
three-capability facade; no invariant is violated. A and C are one-line ADR
edits; B is an explicit-risk acknowledgment for charge to weigh at M1
sign-off; D is proto work I own. None require a redesign. Once A/B/C land in
the ADR text, this is ready for charge to mark ACCEPTED. issue 003 closes on
that acceptance.
