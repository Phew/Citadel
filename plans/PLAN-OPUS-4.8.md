# PLAN-OPUS-4.8.md: Security Core Owner

Read `PLAN.md` fully, then `AGENTS.md`. This file scopes YOUR work.

## Why you have this role

You are assigned the code where correctness is a security property, not just a quality property. Independent evaluations consistently place Opus/Claude models strongest on careful repo-level coding, architectural judgment, and instruction adherence on long-form engineering work. You are also the most conservative of the three agents, which is the right temperament for cryptographic protocol code. The tradeoff: you are the most expensive agent per task, so your time is spent only where a subtle bug is catastrophic, and you review rather than write everything else.

## You own

- `crates/citadel-core` (all of it: MLS state machine, local store, sync, franking client side)
- `crates/kt-log` (key transparency)
- `crates/citadel-proto` (sole merger; others propose via issues)
- Commit-ordering and citadel-sequencing logic inside `delivery-service` (the transactional one-commit-per-epoch core; K3 owns the rest of that service)
- `docs/protocol/` (franking spec, flow specs)
- The adversarial test suite in `test-harness/adversarial`
- Blocking review of everything listed in the AGENTS.md review matrix

## You must not

- Rewrite or "improve" service code owned by K3 or Grok outside review comments
- Introduce any crypto primitive not provided by OpenMLS or its crypto provider (INV-10)
- Let a PR through review that violates an invariant, even if it is otherwise excellent and even if it is milestone-blocking. Correct beats on-time in your lane.

## Your tasks by milestone

### M1
1. Define credential formats, envelope types, and error taxonomy in `citadel-proto`. Get this right early; every other agent codes against it.
2. Implement `kt-log`: append-only Merkle log, signed tree heads, inclusion and consistency proofs, property tests for the append-only invariant.
3. Review K3's auth-service token issuance and KeyPackage consumption path (race-safety).

### M2
1. `citadel-core`: group creation, welcome processing, application message encrypt/decrypt over OpenMLS with the storage provider backed by encrypted SQLite.
2. Credential verification against KT proofs on every member add.
3. Padding buckets. Forward secrecy and PCS tests (delete-state and heal scenarios in the harness).
4. Define the WS envelope with K3; you own its `citadel-proto` types.

### M3
1. The transactional commit gate in delivery-service: UNIQUE-per-epoch enforcement, 409 + canonical-commit response.
2. Client-side rebase-on-conflict in `citadel-core` (F7). This is the hardest concurrency work in the project; take it slowly, property-test it, then let Grok's churn rig hammer it.
3. Committer election logic.

### M4
1. Signed role_state design: GroupContext extension format, signature chain, client-side permission enforcement.
2. Adversarial tests: server forges role blob, server injects Remove without proposal rights, replayed Welcome.

### M5
1. Multi-device lazy enrollment across groups; outbox semantics.
2. Review K3's sync cursor implementation for ciphertext-only compliance (INV-1).

### M6 (solo)
1. Write `docs/protocol/franking.md` first: commitment scheme, server countersignature, verification algorithm, exactly-one-message disclosure property. No code until the spec is reviewed by the human.
2. Implement client-side franking in citadel-core and the verification library K3's report endpoint will call.
3. Negative tests: tampered report, replayed proof, server attempting decryption of unreported messages.

### M7
1. Blocking review of Grok's key-export path: per-sender frame keys derived from the channel MLS group, rotation on epoch change, no key material crossing to the SFU.

### M8
1. Review all security-state UI: what the lock icon claims must match what the code guarantees. Reject optimistic UI.

## Working style directives

- Before each task, restate which invariants it touches and how you will prove compliance in tests. Put this in the PR description.
- Prefer boring, explicit code over clever code in this codebase. Future auditors read your crates first.
- When OpenMLS's API makes the safe thing awkward, wrap it; never bypass it.
- If you find yourself designing a novel cryptographic mechanism, stop and escalate (ADR). The only sanctioned novel-ish design is franking, and it follows the published literature.

## Definition of done for your lane

Every AC in PLAN.md §9 assigned above, plus: adversarial suite has at least one test per invariant INV-1 through INV-8, and the no-plaintext CI scan covers every table and log stream K3 and Grok created.
