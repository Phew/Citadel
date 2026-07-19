# 004: Design review — ADR-0001 (KT log design). Verdict: approve with changes

- **Reporter:** k3 (independent design reviewer, AGENTS.md review matrix)
- **Date:** 2026-07-17
- **Update 2026-07-19:** rev-2 re-review appended below — F1–F4 confirmed
  closed in b35b395; recommend charge marks ADR-0001 ACCEPTED.
- **Blocks:** charge's acceptance of ADR-0001; k3's KT persistence schema (M1)
- **Related:** docs/decisions/0001-kt-log-design.md (PROPOSED, commit d700149),
  crates/kt-log @ e8e29d1, crates/citadel-proto/src/kt.rs @ d11dfcb,
  plans/PLAN.md §6/§7 F1/§13

## Scope of review

Per PLAN-KIMI-K3 M1 task 6: wire contracts checked against citadel-proto,
schema against PLAN.md §6, and every claimed property mapped to a named
acceptance test. I read the full ADR package: ADR-0001, kt-log
(lib.rs/tree.rs/tests/append_only.rs), proto kt.rs/credential.rs, and
docs/issues/001.

## What checks out (verified, not skimmed)

- **Algorithms match the RFCs.** tree.rs implements RFC 6962 §2.1 generation
  and RFC 9162 §2.1.3.2/§2.1.4.2 verification exactly, including the
  `split_point` definition (verified at n=2..5 by hand), empty-tree root =
  SHA-256(""), and the degenerate consistency cases (first=0, first=second,
  first>second) in `consistency_degenerate_cases`.
- **Every Evidence-section claim maps to a real, named test.** CT reference
  roots at sizes 1/2/3/7/8 (`ct_reference_roots`), empty root
  (`empty_tree_root_is_sha256_of_empty_string`), exhaustive inclusion
  (`inclusion_all_indices_all_sizes`, wrong-leaf negatives included),
  exhaustive consistency for all pairs ≤8 (`consistency_all_size_pairs`),
  tamper/fork rejection (`inclusion_rejects_tampered_path_and_wrong_index`,
  `consistency_rejects_forked_history`). §13's independent-oracle bar is met
  for M1 by the pinned CT reference vectors; the Go-oracle upgrade is
  correctly deferred to docs/issues/001.
- **Proptests cover the append-only invariant end-to-end**
  (tests/append_only.rs properties 1–4: old heads/proofs survive appends;
  rewritten history fails consistency; proofs bind to their exact head). The
  history-rewrite test's forgery is honest (rewrites a committed leaf, then
  extends — the adversarial shape that matters).
- **Signer encapsulation is real.** `TreeHeadSigner::sign_head` signs only
  `TreeHeadTbs::signing_input()` built internally; no signing capability
  leaks to auth-service (rule 6 preserved; ADR-0002 facade stays
  three-capability). Signing-domain tags and the length-prefixed
  fixed-layout encodings are pinned by golden-byte tests in proto.
- **Proof/head mismatch is rejected at the API edge**
  (`verify_inclusion` requires proof.tree_size == sth.tree_size;
  `proof_tree_size_must_match_sth`).

## Findings (must resolve before ACCEPTED)

### F1 — KT persistence schema contradicts PLAN.md §6, and neither shape alone suffices

PLAN.md §6 specifies `kt_log(seq, leaf_hash, tree_head, signature,
timestamp)` — an STH-history table. ADR-0001 §4 specifies persisting "full
leaf bytes append-only in PostgreSQL (`kt_log` table)" and rebuilding the
tree at startup — a leaf table. These are different tables, and the ADR
never names the divergence. Worse, *both* are needed: leaf bytes for
inclusion-proof generation and the startup root check, STH history for
serving consistency proofs between historical heads across restarts (a
restarted log holding only the latest STH cannot produce a consistency
proof from an older client-pinned head... unless it re-signs history, which
it must never do silently).

**Proposed fix:** amend the ADR to define the physical schema explicitly —
suggestion: `kt_leaves(seq BIGSERIAL PRIMARY KEY, leaf_bytes BYTEA NOT
NULL)` (append-only, the rebuild source) and `kt_sth(tree_size BIGINT
PRIMARY KEY, root_hash BYTEA NOT NULL, signed_at TIMESTAMPTZ NOT NULL,
signature BYTEA NOT NULL)` (every STH ever issued, insert-only) — and note
that it supersedes PLAN.md §6's `kt_log` row (AGENTS.md rule 5 doc
amendment). Until the ADR says this, auth-service has no canonical schema
to migrate; my KT persistence PR is blocked on it.

### F2 — Log public-key distribution is unspecified (trust bootstrap hole)

ADR §5 says "clients pin the log public key" but never says how the key
reaches the client. F1 step 5 has the client verify its own inclusion at
registration — against a key it has no reason to trust yet (a fetched key
would be circular: the log vouches for the log). A dishonest server could
hand each client a different log key and equivocate undetectably even in
principle.

**Proposed fix:** state the mechanism in the ADR. Acceptable for v1:
log public key pinned in client builds (or distributed with the client
artifact, verified via the release channel), with TOFU documented as an
explicit threat-model gap otherwise. One precise paragraph suffices; the
implementation cost is small, the honesty cost of omitting it is not.

## Findings (minor; fix in the referenced code, no re-review needed)

### F3 — u16 length prefix on `handle` wraps past 65,535 bytes (proto kt.rs `KtLeaf::leaf_bytes`)

`(handle.len() as u16).to_be_bytes()` silently truncates for handles ≥
65,536 bytes. Today the following fields are fixed-width, so encodings stay
distinct and no collision results — but the prefix then lies about the
field boundary, a latent encoding-integrity footgun the moment any later
field becomes variable-width.

**Proposed fix:** cap handle length at registration (auth-service
validation, suggest ≤ 64 bytes — product-sensible regardless) AND a
`debug_assert!(handle.len() <= u16::MAX as usize)` (or hard assert) in
`leaf_bytes()`. Alternatively widen the prefix to u32; the cap is cheaper.

### F4 — Startup root-mismatch check (ADR §4) has no named acceptance test

ADR §4 requires auth-service to fatal-error at startup when the rebuilt
root mismatches the last persisted STH. §13 requires claimed properties to
name their test. The property is assigned to my lane ("auth-service
persistence and startup-check implementation is K3's M1 lane with Opus
review"); no test name exists for charge to hold me to.

**Proposed fix:** add to the ADR's Evidence section:
`auth-service tests/kt_persistence.rs::startup_fails_on_tampered_leaf_bytes`
(K3 to deliver with the KT persistence PR).

## Non-blocking notes

- `RegisterAccountResponse` carries `kt_leaf_index` + `kt_tree_head` but not
  the audit path; F1 step 5 verification needs a follow-up
  `GET /v1/kt/proof`. The two-step works (proof must be requested at the
  STH's exact tree_size); one sentence in the future auth.md should pin the
  intended flow so clients don't "verify" against a fresh head instead.
- `KtLog::consistency_proof` rejects `first == 0`; RFC-trivial consistency
  from the empty tree is unnecessary for clients that pin from their first
  observed STH. Fine as designed.
- The ADR's honest-gaps list (detection-not-prevention, no gossip, handles
  in leaf bytes, O(n) rebuild) is complete and correctly scoped to the
  threat-model doc. This is the standard other docs should meet.

## Recommendation

Approve ADR-0001 after F1 and F2 land as an ADR amendment (or a short
superseding note); F3/F4 are small and trackable. The design itself —
RFC 6962 exactly, encapsulated signing, proto-owned encodings — is the
right call, and the evidence package meets §13.

---

## Rev-2 re-review (k3, 2026-07-19) — F1–F4 confirmed closed; recommend ACCEPT

Re-reviewed ADR-0001 rev 2 (commit `b35b395`, on main via PR #2) against
each finding. All four are resolved in full; nothing from this review
remains open. One non-blocking forward note at the end.

### F1 — CLOSED (checked hardest; my KT persistence builds on this schema)

§4 now defines the physical schema explicitly, in the shape this review
proposed: `kt_leaves(seq BIGSERIAL PRIMARY KEY, leaf_bytes BYTEA NOT NULL)`
(insert-only rebuild source; sole input to inclusion-proof generation and
the startup root check) and `kt_sth(tree_size BIGINT PRIMARY KEY, root_hash
BYTEA, signed_at TIMESTAMPTZ, signature BYTEA)` (insert-only STH history).
Verified against the original finding point by point:

- The PLAN.md §6 divergence is named and superseded in the ADR text
  ("supersedes that row (AGENTS.md rule 5 doc amendment)") — the doc
  amendment rule is honored, not just asserted.
- Both required purposes are covered without re-signing: inclusion proofs
  rebuild from full leaf bytes; a restarted log serves a consistency proof
  between a client-pinned old STH and a newer one from `kt_sth` history —
  never a re-signed divergent head (INV-4).
- Crash consistency is addressed: a leaf append and the STH covering it
  commit in one transaction, so `kt_sth` cannot lag or lead `kt_leaves`.
- The startup root check is specified as MUST fatal-error on mismatch —
  the property F4's named test pins.
- One schema subtlety the ADR pins correctly, which my persistence PR will
  honor: `seq` BIGSERIAL is 1-based while the RFC 6962 leaf index is
  0-based — leaf index = seq - 1, owned by auth-service and pinned in a
  test. Without that sentence the off-by-one would have been mine to trip.

### F2 — CLOSED (exceeds the bar this review set)

§5 specifies compile-time embedded Ed25519 anchor distribution — no
runtime key fetch, no TOFU window (stronger than the "TOFU documented as
an explicit gap" fallback I offered); key_id-based rotation via client
release with an ordered `{current, next?}` anchor set; and monotonic
client anti-rollback state that rejects a smaller `tree_size` outright
and requires a valid consistency proof from the pinned head before
advancing. The residual split-view equivocation gap is stated honestly as
out of scope for v1 (needs out-of-band gossip), with v1's claim scoped
precisely. Evidence names `citadel-core`'s
`kt_client_rejects_rollback_and_fork`.

### F3 — CLOSED (verified in code, not just in the ADR)

`KtLeaf::leaf_bytes()` in `crates/citadel-proto/src/kt.rs` (`b35b395`)
carries `debug_assert!(handle.len() <= u16::MAX as usize)` with a comment
pointing at the registration cap. The enforcing guard is ADR-0003 §6's
1–64-byte handle limit at registration — note the coupling: that cap
rides on ADR-0003's acceptance (Opus review in docs/issues/005 folded
2026-07-19; awaiting charge's ACCEPTED).

### F4 — CLOSED

The Evidence section names exactly the proposed test:
`auth-service tests/kt_persistence.rs::startup_fails_on_tampered_leaf_bytes`.
Delivery is my lane with the KT persistence PR; the name is now
contractual per §13.

### Non-blocking forward note (not a finding)

ADR-0001 §5's key_id rotation arrives via the proto follow-up — landed on
main 2026-07-19 (PR #7: key_id on tree heads + KT proof/head wrapper).
When auth-service adopts the key_id-carrying `SignedTreeHead`, `kt_sth`
will need a `key_id` column to serve rotated STHs unambiguously — during a
rotation overlap two anchors are live and the serving row must say which
one signed it. Cheap to add in the same PR that adopts key_id; flagging
so it is not lost. Single-key v1 is unaffected.

### Verdict

F1–F4 resolved in full. ADR-0001 rev 2 is approved from the K3 review
seat; recommend charge marks it ACCEPTED.
