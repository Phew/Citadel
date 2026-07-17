# Issue 002: Request to K3 — cargo-deny bans enforcing the crypto facade

- **Raised by:** Opus, 2026-07-17
- **Owner:** K3 (CI hardening lane, M1); Opus blocking review
- **Related:** AGENTS.md rule 6, ADR-0002, crates/citadel-service-crypto

## Request

Wire cargo-deny `[bans]` (or an equivalent CI check) so that the four
service crates — auth-service, delivery-service, directory-service,
blobstore-service — cannot take *direct* dependencies on crypto primitive
crates. Suggested deny list to start: `ed25519-dalek`, `sha2`, `sha1`,
`md-5`, `ring`, `aes-gcm`, `chacha20poly1305`, `hmac`, `hkdf`, `rand`,
`rand_core`, `getrandom`.

Sanctioned wrappers (may depend on the above): `citadel-service-crypto`
(verify/sha256/random, ADR-0002) and `kt-log` (encapsulated tree-head
signing, ADR-0001 §3). Transitive deps via the wrappers are fine; the check
targets direct edges in the service crates' Cargo.toml.

Note: cargo-deny bans are workspace-global with `wrappers` exceptions —
`[[bans.deny]]` with `wrappers = ["citadel-service-crypto", "kt-log"]`
should express this directly. If a service later has a legitimate transitive
need (e.g. sqlx pulling `sha2`), scope with `deny-multiple-versions`-style
graph checks rather than loosening the wrapper list; escalate if it gets
ugly.

## Acceptance

CI fails if a service crate adds a direct crypto dependency; a test PR
demonstrating the failure is linked as evidence.
