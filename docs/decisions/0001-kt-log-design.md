# ADR-0001: Key transparency log design (RFC 6962 shape, encapsulated tree-head signing)

- **Status:** PROPOSED
- **Date:** 2026-07-17
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3 (required before acceptance per AGENTS.md).
- **Invariants touched:** INV-4, INV-9, INV-10
- **Related:** plans/PLAN.md §7 F1, §9 M1, §13; plans/AGENTS.md rule 6; crates/kt-log; crates/citadel-proto/src/kt.rs; docs/issues/001

## Context

M1 requires an append-only key transparency log for identity keys: signed
tree heads, inclusion proofs (client verifies its own registration, F1 step
5), and consistency proofs (clients detect history rewrites). Constraints:
INV-10 (no novel crypto), INV-4 (clients verify everything), and AGENTS.md
rule 6 (services touch crypto only via the verify/sha256/random facade) —
yet auth-service must produce *signed* tree heads, which is a signing
capability.

## Decision

1. **RFC 6962 exactly.** Leaf hash `SHA-256(0x00||leaf)`, node hash
   `SHA-256(0x01||l||r)`, MTH/PATH/PROOF generation per RFC 6962 §2.1,
   verification per RFC 9162 §2.1.3.2/§2.1.4.2. No custom tree shape, no
   sparse-Merkle/versioned-map design in v1 (that is what full KT systems
   like Parakeet/SEEMless use; our v1 threat model needs only append-only
   identity-key binding with client-verifiable membership).
2. **Wire shapes in citadel-proto** (`kt.rs`): `KtLeaf` (account_id, handle,
   identity_pubkey, appended_at) with deterministic domain-separated
   encoding (`citadel/v1/kt-leaf`); `TreeHeadTbs` signing input under
   `citadel/v1/kt-tree-head`. One contract for server generation and client
   verification.
3. **Tree-head signing is encapsulated in kt-log**, not added to the service
   crypto facade. `TreeHeadSigner::sign_head` signs only
   `TreeHeadTbs::signing_input()` built internally; auth-service holds the
   type but cannot sign arbitrary bytes. The facade stays three-capability
   (verify, sha256, random). The log key is a server operational key (seed
   from auth-service's secret store), not user key material — INV-2 is not
   implicated.
4. **Persistence:** auth-service persists full leaf bytes append-only in
   PostgreSQL (`kt_log` table); kt-log rebuilds the in-memory hash tree at
   startup and MUST fatal-error if the rebuilt root mismatches the last
   persisted STH.
5. **Client policy (M1/M2):** clients pin the log public key, verify their
   own inclusion at registration, and verify consistency between any two
   STHs they observe. Gossip/auditor infrastructure is out of scope for v1
   and listed in the threat model as a known gap (a server can still
   equivocate per-client until STHs are compared out of band).

## Alternatives considered

1. **Versioned key directory (SEEMless/Parakeet-style VRF map)** — stronger
   privacy (hides handles) and per-key version semantics; substantially more
   novel crypto surface (VRFs, ZK inclusion), conflicts with the spirit of
   INV-10 and M1 scope. Deferred; the RFC 6962 log is forward-compatible as
   the transparency backbone.
2. **Signing via the service crypto facade** — adding `sign()` to the facade
   gives every service a general signing capability; rule 6 calls that a
   design smell. Encapsulation in kt-log is strictly narrower.
3. **Trillian or other external log service** — operationally heavy, Go
   dependency in the serving path, and unnecessary for a single-operator log.

## Consequences

- Positive: small auditable surface; independent test vectors exist (CT
  reference roots); client verification is pure Rust reusable in
  citadel-core; no new primitive beyond SHA-256 + Ed25519.
- Negative: no equivocation *prevention* (detection only, and only when
  clients compare STHs); handles appear in leaf bytes (log is not public in
  v1; revisit if it ever becomes public). Full-tree rebuild at startup is
  O(n) — fine for v1 scale, revisit with checkpointing if the log grows
  past ~10^7 leaves.
- Follow-ups: docs/issues/001 (import of previously verified Merkle oracle);
  STH gossip design deferred to threat-model doc; auth-service persistence
  and startup-check implementation is K3's M1 lane with Opus review.

## Evidence

- `kt-log/src/tree.rs` tests: CT reference roots (sizes 1,2,3,7,8),
  SHA-256("") empty root, exhaustive inclusion (all indices, sizes ≤8),
  exhaustive consistency (all pairs ≤8), tampered-path and forked-history
  rejection.
- `kt-log/tests/append_only.rs` proptests: appends preserve old heads and
  proofs; any rewrite of committed history fails consistency; proofs bind
  to their exact tree head.
- Proposed (docs/issues/001): cross-validation against a Go oracle
  implementing the same RFC algorithms.
