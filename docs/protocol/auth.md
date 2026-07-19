# Protocol: registration and key-transparency verification (F1)

- **Status:** DRAFT (M1). Normative for the client KT verification flow.
- **Owner:** Opus (protocol/); auth-service implementation is K3's lane.
- **Canonical for:** the *sequence and verification obligations* of PLAN.md
  §7 F1. Wire shapes are canonical in `citadel-proto` (AGENTS.md rule 5);
  operational parameters (challenge/token TTLs, handle rules, pool sizing) are
  canonical in ADR-0003. Where this doc and those diverge, they are the
  authority for their surface and this doc is amended.
- **Related:** ADR-0001 (KT log design; §5 log-key distribution + anti-rollback),
  ADR-0003 (auth-flow parameters; §5 KT proof endpoint), `citadel-proto/src/kt.rs`,
  `crates/kt-log`, PLAN.md §7 F1 / §8, INV-4, INV-5, INV-9, INV-10.

This document pins the part of F1 a client must get exactly right: how it
verifies that the key-transparency (KT) log has honestly recorded its identity
key, and how it keeps verifying that the log only ever grows and never forks.
Everything here is client-side verification against a server the client does
not trust (INV-4); the server operates the log, the client checks it.

---

## 1. The trust anchor (what the client starts from)

The KT log signs each tree head with an Ed25519 **log key**. The client
verifies signatures against the log's **public** key, which must reach the
client through a channel the server does not control — otherwise the bootstrap
is circular (the log vouching for itself) and a dishonest server can hand each
client a different key and equivocate undetectably (ADR-0001 §5).

- **Distribution: compile-time embedded anchor.** The log public key is a
  pinned constant compiled into the client build and shipped inside the
  reproducible client artifact via the release channel. It is **never fetched
  from auth-service.** There is no first-use / TOFU window: a head the client
  cannot verify against an embedded anchor is rejected, with no
  fetch-the-key fallback (the fallback *is* the hole).

- **Anchor set + `key_id`.** To allow key rotation without a flag day, the
  client embeds an ordered anchor set `{current, next?}`. Every tree head
  carries a `key_id` = `SHA-256(log_public_key)` (`TreeHeadTbs.key_id`, the
  RFC 6962 §3.2 LogID construction — no novel crypto, INV-10). The client
  derives a `KeyId` from each embedded anchor by hashing it once, then:

  > A signed tree head is accepted **iff** its `key_id` names an embedded
  > anchor **and** its signature verifies under that anchor.

  The `key_id` is inside the signed input, so a signature can never be
  relabelled as if made under a different anchor. Rotating the log key is a
  client release (the anchor is compiled in); removing a retired anchor is a
  later release. **No runtime key fetch, ever.**

`kt-log::verify_tree_head` implements the single-anchor case of this check
(match `key_id`, then verify signature). Selecting among an anchor *set* is the
client's responsibility and lands with the citadel-core KT client.

---

## 2. Client anti-rollback state

A pinned key stops key *substitution*. It does **not** by itself stop the
server replaying a shorter, older-but-validly-signed history (truncation /
rollback) or showing a forked one. So the client persists monotonic
anti-rollback state in its encrypted local store:

> `anchor_state = (tree_size, root_hash)` — the highest tree head this client
> has ever accepted.

It is seeded at first contact (registration, §3) from the STH returned there,
verified under the embedded anchor, and advanced only by the §4 check. It is
never rewound. Losing it (e.g. fresh install) re-seeds from the current STH —
a client with no history cannot detect a rollback that predates its first
observation; this is inherent and stated in the threat model, not a bug.

---

## 3. Registration and self-inclusion (F1, the two-step verify)

At registration the client proves the log actually recorded *its own* identity
key. PLAN.md §7 F1:

1. Client generates an identity keypair (Ed25519) and first device keypair.
2. `POST /v1/accounts` with handle + identity public key. The server creates
   the account, **appends the identity key as a KT leaf**, and returns the
   signed tree head (`SignedTreeHead`) covering a tree that includes the new
   leaf. Call its size `S` and note the client's assigned `leaf_index`.
3. Client builds its MLS device credential (binds device key → identity key).
4. Client generates N=100 KeyPackages and uploads them (ADR-0003 §4).
5. **Client verifies its own KT inclusion — the two-step verify:**

   **Step A — fetch the proof at the pinned tree size.**
   `GET /v1/kt/proof?leaf=<leaf_index>&tree_size=<S>`. The response is a single
   `KtProofResponse { proof, signed_tree_head }` (ADR-0003 §5): the inclusion
   proof **and** the exact head it verifies against, returned atomically. The
   explicit `tree_size=<S>` and the paired head close the TOCTOU window where
   the log grows between a fetch-proof and a fetch-head call and the client is
   handed a proof and head that no longer match. The client MUST NOT verify a
   proof against a *freshly* fetched latest head; it verifies against the head
   the proof was issued for.

   **Step B — verify under the embedded anchor.** In order, all mandatory:
   1. `signed_tree_head` is accepted per §1 (key_id names an embedded anchor;
      signature verifies under it). Reject otherwise.
   2. `proof.tree_size == signed_tree_head.tbs.tree_size == S`, and
      `proof.leaf_index == leaf_index`. A proof against a different tree proves
      nothing about this head (`kt-log::verify_inclusion` enforces the size
      match).
   3. The RFC 9162 inclusion proof verifies: the leaf hash
      `SHA-256(0x00 || KtLeaf::leaf_bytes())` — where `KtLeaf` is rebuilt from
      the client's *own* `account_id`, handle, identity public key, and the
      server-reported append timestamp `RegisterAccountResponse.kt_appended_at`
      (returned at registration, step 2 — the one leaf field the client cannot
      derive itself) — combined with `audit_path` reproduces
      `signed_tree_head.tbs.root_hash`. This is the honesty-critical step: the
      client checks the log committed to **its** key, not just to *some* tree.
   4. Seed `anchor_state = (S, root_hash)` (§2).

   If any step fails, registration is not trusted: surface the failure, do not
   proceed to use the account. A server that cannot produce a valid
   self-inclusion proof has not honestly registered the client.

---

## 4. Ongoing tree-head acceptance (anti-rollback + anti-fork)

Every later tree head the client observes (polling `GET /v1/kt/tree-head`, or
the head paired with any `GET /v1/kt/proof`) is accepted only through this
check, evaluated against the stored `anchor_state = (last_size, last_root)`:

1. **Signature/anchor** — accept the new head per §1, else reject.
2. **Monotonicity** — `new.tree_size >= last_size`. A smaller tree is a
   rollback: **hard reject, surface to the user, never silently downgrade**
   (INV-5 in spirit). Equal size MUST also carry the same `root_hash`; a
   different root at equal size is equivocation → reject.
3. **Consistency** — fetch a consistency proof from `last_size` to
   `new.tree_size` and verify it (RFC 9162 §2.1.4.2,
   `kt-log::verify_consistency`): the new head must provably **extend** the
   pinned one. A forked history — same or larger size, incompatible contents —
   fails here.
4. **Advance** — only if 1–3 pass, set `anchor_state = (new.tree_size,
   new.root_hash)`.

From first contact on, the log can only ever be caught **growing
consistently** for this client — never shrinking, never forking.

---

## 5. Endpoints and shapes (client view)

All under `/v1`; see PLAN.md §8 and `citadel-proto`.

| Method / path | Response type | Notes |
|---|---|---|
| `POST /accounts` | `SignedTreeHead` (+ account/leaf ids) | Appends the identity leaf; returns the head covering it. |
| `GET /kt/tree-head` | `SignedTreeHead` | Latest STH. Verified per §1, accepted per §4. |
| `GET /kt/proof?leaf=<i>[&tree_size=<n>]` | `KtProofResponse` | Proof **and** the head it verifies against, atomically (ADR-0003 §5). `tree_size` defaults to the latest STH; pin it for self-inclusion (§3). |
| `GET /kt/consistency?first=<a>&second=<b>` | `ConsistencyProof` | For §4 step 3. (Endpoint pinned when the persistence PR lands; K3 lane.) |

Signing inputs are the `signing_input()` builders in `citadel-proto`
(domain-separated under `citadel/v1/...`, golden-byte pinned). Clients and the
server verify against one contract (INV-4); clients never hand-roll these
bytes.

---

## 6. Residual gap (stated honestly)

The embedded anchor + anti-rollback state defeat key **substitution** and
**rollback/fork** against a single client. They do **not** defeat *split-view
equivocation*: a single operator holding the genuine log key can sign two
internally consistent histories and show them to disjoint client sets. Only
out-of-band STH gossip or an independent auditor closes that, and gossip is out
of scope for v1 (ADR-0001 §5 residual gap; threat-model doc).

v1's precise claim: **a client cannot be given a forged or rolled-back log it
will accept; clients cannot yet cross-check that they were all shown the same
log.**

---

## 7. Named tests (hold the lane to this flow, PLAN.md §13)

- `citadel-core` client: `kt_client_verifies_own_inclusion_at_registration`
  — the §3 two-step verify accepts a genuine proof+head and rejects a proof
  whose leaf is not the client's own key, and one paired with a head the client
  cannot anchor.
- `citadel-core` client: `kt_client_rejects_rollback_and_fork` — a shorter STH
  is rejected (§4.2); a forked equal-or-larger STH fails the consistency proof
  (§4.3); a genuine extension is accepted and advances `anchor_state`.
- `kt-log`: `verify_tree_head` accepts a head whose `key_id` names the pinned
  anchor and rejects one that names another (`verify_rejects_key_id_that_names_another_anchor`).
- `citadel-proto`: `KtProofResponse` pairs a proof with the head of the same
  `tree_size` (`kt_proof_response_roundtrip`).

(Client tests are delivered with the citadel-core KT client in M1/M2; named
here so charge can hold the lane to the property.)
