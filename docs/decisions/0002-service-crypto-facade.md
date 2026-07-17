# ADR-0002: citadel-service-crypto — the three-capability service crypto facade

- **Status:** ACCEPTED (charge, 2026-07-17, recorded by advisor)
- **Date:** 2026-07-17
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3.
- **Invariants touched:** INV-1, INV-2, INV-9, INV-10
- **Related:** plans/AGENTS.md rule 6; crates/citadel-service-crypto; ADR-0001 (signing carve-out)

## Context

AGENTS.md rule 6 mandates that server-side services touch cryptography only
through an Opus-owned facade exposing verify, sha256, and OS-CSPRNG bytes.
This ADR records the concrete crate design and the enforcement plan so the
rule is checkable rather than aspirational.

## Decision

1. **Crate:** `citadel-service-crypto` exposes exactly:
   - `verify(pk32, msg, sig64)` — Ed25519 via ed25519-dalek `verify_strict`
     (rejects small/mixed-order components; cheap malleability insurance);
   - `sha256(data)` — via the `sha2` crate;
   - `random_bytes(buf)` / `random_array::<N>()` — via `getrandom` (OS
     CSPRNG, INV-9). RNG failure is a fatal error; no fallback source.
2. **Deliberately absent:** signing, key generation, encryption, decryption,
   KDFs, MACs. Services hold no user keys (INV-2) and no plaintext (INV-1).
   The single sanctioned exception is tree-head signing, encapsulated inside
   kt-log (ADR-0001 §3), which does not flow through or extend this facade.
3. **Message bytes discipline:** callers pass the deterministic signing
   inputs defined in citadel-proto (`signing_input()` builders); services
   never construct signing inputs ad hoc.
4. **Enforcement (K3's CI lane, Opus review):** cargo-deny `bans` deny
   direct dependencies on crypto crates (ed25519-dalek, sha2, ring, rustls'
   crypto internals, rand for key-material paths, etc.) from
   auth-service / delivery-service / directory-service / blobstore-service,
   with the facade and kt-log as the only wrappers. Until the bans list
   lands, review is the enforcement.

## Alternatives considered

1. **Each service depends on primitive crates directly** — smallest code,
   but the "no fourth capability" property becomes unauditable; exactly what
   rule 6 exists to prevent.
2. **Re-export OpenMLS provider primitives** — drags group-crypto machinery
   into services that must never link decryption paths (INV-1); wrong
   dependency direction.
3. **`ring` instead of dalek/sha2** — fine primitives, but ed25519-dalek is
   already the transitive base of the OpenMLS rust-crypto provider, keeping
   one Ed25519 implementation across the workspace.

## Consequences

- Positive: one small file is the entire service crypto surface; auditors
  read ~80 lines; INV-9 has a single choke point.
- Negative: a genuinely new service need (e.g. HMAC for franking
  countersignature in M6) forces an escalation and ADR. That is intended
  friction — M6 will get its own ADR rather than a quiet facade extension.
- Follow-ups: deny.toml bans wiring (K3, M1 CI hardening); M6 franking
  countersignature capability review.

## Evidence

- Unit tests: valid/tampered/wrong-key/invalid-encoding verify cases, NIST
  SHA-256("abc") vector, CSPRNG fill-and-vary.
- Future: cargo-deny bans check in CI proving services import no primitive
  crates directly.
