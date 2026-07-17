# ADR-0001: Key transparency log design (RFC 6962 shape, encapsulated tree-head signing)

- **Status:** PROPOSED
- **Date:** 2026-07-17 (rev 2)
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3 (required before acceptance per AGENTS.md).
- **Invariants touched:** INV-2, INV-4, INV-5, INV-9, INV-10
- **Related:** plans/PLAN.md §6, §7 F1, §9 M1, §13; plans/AGENTS.md rules 5, 6; crates/kt-log; crates/citadel-proto/src/kt.rs; docs/issues/001; docs/issues/004 (K3 design review); docs/decisions/0003 (auth params)

## Revision history

- **rev 1** (commit `d700149`): initial PROPOSED design. K3 design-reviewed it in
  docs/issues/004: "approve with changes" — F1 (persistence schema), F2 (log
  public-key distribution / trust bootstrap), F3 (u16 handle prefix), F4 (named
  startup-check test).
- **rev 2** (this commit): resolves issue 004 in full. §4 now defines the physical
  persistence schema (F1); a new §5 specifies log-key distribution and the
  client anti-rollback bootstrap (F2); §6 (formerly §5) folds in the F4 test name;
  F3 is fixed in code (`citadel-proto/src/kt.rs`, this commit) and noted below.
  This supersedes rev 1 where they differ. Still PROPOSED — only charge marks it
  ACCEPTED (AGENTS.md rule 3), after re-review.

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
   implicated by the *private* half. The *public* half is a trust anchor and
   is handled in §5.

4. **Persistence (F1 — resolves issue 004 F1).** PLAN.md §6's single
   `kt_log(seq, leaf_hash, tree_head, signature, timestamp)` row conflated
   two tables that serve different, both-required purposes. This ADR
   supersedes that row (AGENTS.md rule 5 doc amendment) with two insert-only
   tables:

   ```sql
   -- Append-only leaf source. Rebuilt into the in-memory hash tree at
   -- startup; the sole input to inclusion-proof generation and the
   -- startup root check. `seq` is the RFC 6962 leaf index (0-based logical;
   -- BIGSERIAL is 1-based, so leaf index = seq - 1 — auth-service owns that
   -- mapping and pins it in a test).
   kt_leaves (
       seq        BIGSERIAL   PRIMARY KEY,
       leaf_bytes BYTEA       NOT NULL      -- KtLeaf::leaf_bytes(), the signed pre-image
   );

   -- Every signed tree head ever issued, insert-only, keyed by tree size.
   -- Needed so a restarted log can serve a consistency proof between an old
   -- client-pinned STH and a newer one WITHOUT re-signing history (which it
   -- must never do — a re-signed divergent head is an equivocation, INV-4).
   kt_sth (
       tree_size  BIGINT      PRIMARY KEY,
       root_hash  BYTEA       NOT NULL,
       signed_at  TIMESTAMPTZ NOT NULL,
       signature  BYTEA       NOT NULL
   );
   ```

   Rules: (a) both tables are insert-only — no `UPDATE`/`DELETE` in normal
   operation (an operational purge is an out-of-band, audited action, not a
   code path). (b) A leaf append and the STH that covers it commit in one
   transaction, so `kt_sth` never lags or leads `kt_leaves` across a crash.
   (c) At startup kt-log rebuilds the tree from all `kt_leaves` in `seq`
   order and MUST fatal-error if the recomputed root for `tree_size = N`
   does not equal `kt_sth.root_hash` at `tree_size = N` (tamper / partial
   write detection). (d) STHs are served from `kt_sth`, never re-signed on
   read. auth-service owns the migration and the store; kt-log owns the
   rebuild-and-verify logic. This unblocks K3's KT persistence PR.

5. **Log-key distribution and client trust bootstrap (F2 — resolves issue
   004 F2; the honesty-critical one).** The client verifies its own
   inclusion at registration (F1 step 5) and every later STH against the log
   *public* key. That key must reach the client through a channel the server
   does not control, or the bootstrap is circular (the log vouching for the
   log) and a dishonest server can hand each client a different key and
   equivocate undetectably even in principle.

   - **Distribution: compile-time embedded anchor.** The log public key (an
     Ed25519 verifying key) is embedded in the client build as a pinned
     constant, shipped inside the reproducible client artifact via the
     release channel — never fetched from auth-service. `GET /v1/kt/tree-head`
     returns only the signed head; the client validates the signature with
     the embedded key and rejects any head it cannot verify (no
     fetch-the-key fallback — that fallback *is* the hole). This is a
     hard-pinned anchor, not TOFU: there is no first-use window in which an
     attacker-supplied key is accepted.
   - **Key rotation is a client release.** Because the anchor is compiled in,
     rotating the log key requires shipping a new client. To allow overlap,
     the client embeds an ordered anchor set `{current, next?}` and a
     `key_id` is included in `TreeHeadTbs` (proto change tracked below); an
     STH verifies iff its `key_id` names an embedded anchor and the signature
     checks under that anchor. Removing a retired anchor is a later release.
     No runtime key fetch, ever.
   - **Anti-rollback state (the anchor is necessary but not sufficient).** A
     pinned key stops key *substitution*; it does not by itself stop the
     server replaying a shorter, older-but-validly-signed history
     (truncation / rollback). So the client persists monotonic anti-rollback
     state — the highest `(tree_size, root_hash)` STH it has ever accepted —
     and enforces, on every new STH:
       1. `new.tree_size >= last.tree_size` (a smaller tree is a rollback →
          hard reject, surface to the user, never silently downgrade —
          INV-5 in spirit);
       2. a valid RFC 9162 **consistency proof** from `last` to `new` (the
          new head provably extends the pinned one; a forked history fails
          here);
       3. only then advance the stored state to `new`.
     This state lives in the client's encrypted local store. First contact
     seeds it from the STH returned at registration (verified under the
     embedded anchor); from then on the log can only ever be caught growing
     consistently, never shrinking or forking, *for that client*.
   - **Residual gap (stated honestly, belongs in the threat-model doc).** The
     embedded anchor + anti-rollback state defeat key substitution and
     rollback against a single client. They do **not** defeat *split-view
     equivocation*: a single operator holding the genuine key can still sign
     two consistent-looking histories shown to disjoint client sets. Only
     out-of-band STH gossip / an independent auditor closes that, and gossip
     is out of scope for v1 (§ Consequences, and docs/issues future item).
     v1's claim is therefore precise: "clients cannot be given a forged or
     rolled-back log they will accept; clients cannot yet cross-check that
     they were all shown the *same* log."

6. **Client policy (M1/M2 — was rev-1 §5).** Clients pin the log public key
   per §5, verify their own inclusion at registration, and verify
   consistency between any two STHs they observe (enforced as the §5
   anti-rollback check). Gossip/auditor infrastructure is out of scope for
   v1 and listed in the threat model as a known gap (a single operator can
   still split-view per §5's residual gap until STHs are compared out of
   band).

### F3 fix (issue 004 F3) — done in code this commit

`citadel-proto/src/kt.rs::KtLeaf::leaf_bytes` now carries a
`debug_assert!(handle.len() <= u16::MAX)` documenting and enforcing the
encoder's side of the length-prefix contract, with a comment pointing at the
registration cap. The actual guard is ADR-0003 §6's 1–64-byte handle limit
at registration; the assert catches any violation of that contract in
tests/debug rather than letting a wrapped prefix silently corrupt a leaf.
(A u16 cap of 64 bytes leaves a 1000× margin; widening the prefix to u32 was
the alternative and is unnecessary given the cap.)

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
4. **Fetch-and-TOFU the log key** (rejected for F2) — the client trusts the
   first log key it is served. Rejected: it opens a first-use substitution
   window and makes the F1 step-5 self-check circular. The compile-time
   anchor removes the window entirely at the cost of tying key rotation to a
   client release — the right trade for a security anchor.
5. **Single STH table only** (PLAN §6 shape) — cannot regenerate inclusion
   proofs or run the startup root check without the leaf bytes; forces
   re-signing to serve old consistency proofs. Rejected per §4.

## Consequences

- Positive: small auditable surface; independent test vectors exist (CT
  reference roots); client verification is pure Rust reusable in
  citadel-core; no new primitive beyond SHA-256 + Ed25519. The trust anchor
  is honest (no first-use window) and rollback/fork are caught client-side.
- Negative: no equivocation *prevention* against a single operator
  (detection only, and split-view still needs out-of-band gossip — §5
  residual gap); handles appear in leaf bytes (log is not public in v1;
  revisit if it ever becomes public). Full-tree rebuild at startup is O(n) —
  fine for v1 scale, revisit with checkpointing if the log grows past ~10^7
  leaves. Log-key rotation requires a client release (accepted; §5).
- Proto follow-up (sole-merger, me): add `key_id` to `TreeHeadTbs` and a
  `SignedTreeHead` that carries it, so §5 rotation and the ADR-0003 §5
  proof+head wrapper are one coherent change. Golden-byte tests updated in
  the same PR. Tracked so K3's auth-service codes against a stable shape.
- Follow-ups: docs/issues/001 (import of previously verified Merkle oracle);
  STH gossip / split-view defense deferred to the threat-model doc;
  auth-service persistence, migration, and startup-check implementation is
  K3's M1 lane with Opus review (§4).

## Evidence

- `kt-log/src/tree.rs` tests: CT reference roots (sizes 1,2,3,7,8),
  SHA-256("") empty root, exhaustive inclusion (all indices, sizes ≤8),
  exhaustive consistency (all pairs ≤8), tampered-path and forked-history
  rejection.
- `kt-log/tests/append_only.rs` proptests: appends preserve old heads and
  proofs; any rewrite of committed history fails consistency; proofs bind
  to their exact tree head.
- **Startup root check (F4 — issue 004 F4):**
  `auth-service tests/kt_persistence.rs::startup_fails_on_tampered_leaf_bytes`
  — persist leaves + STH, corrupt a `kt_leaves.leaf_bytes` row, assert the
  log refuses to start because the rebuilt root ≠ persisted `kt_sth.root_hash`
  (K3 delivers this test with the KT persistence PR; named here so the lane
  is held to the property, per §13).
- **Anti-rollback (F2):** `citadel-core` client test
  `kt_client_rejects_rollback_and_fork` — a shorter STH (`tree_size` below
  the stored anchor state) is rejected; a forked equal-or-larger STH fails
  the consistency proof from the pinned head; a genuine extension is
  accepted and advances the state (delivered with the citadel-core KT client
  in M1/M2; named here per §13).
- **F3:** `citadel-proto/src/kt.rs` golden-byte leaf tests plus the new
  `debug_assert` on handle length; ADR-0003 §6 registration cap is the
  enforcing guard.
- Proposed (docs/issues/001): cross-validation against a Go oracle
  implementing the same RFC algorithms.
