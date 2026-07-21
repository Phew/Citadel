# ADR-0005: M2 DM delivery + wire model (F2 Welcome, F4 send/receive)

- **Status:** PROPOSED (author: Opus; design review: K3; charge is sole approver). Build (delivery-service transport, citadel-core MLS path) does not start until charge accepts.
- **Date:** 2026-07-20
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3.
- **Invariants touched:** INV-1 (no plaintext server-side; canary extends to delivery tables), INV-2 (keys never leave the client; local store key in OS keychain), INV-3 (server proposes, never decides), INV-4 (clients validate every welcome/commit/credential), INV-6 (deterministic commit ordering — *reserved* here, enforced in M3), INV-8 (franking, not scanning — scoping call below), INV-9 (local DB key + idempotency randomness from the OS CSPRNG), INV-10 (no crypto primitives from scratch — padding + SQLite-at-rest scoping calls below)
- **Related:** plans/PLAN.md §7 F2/F4, §8 (groups/messages, gateway), §9 M2, §10 (adversarial + no-plaintext), §13; docs/decisions/0001 (KT log), 0002 (crypto facade), 0003 (auth params — `validate_token`, KeyPackage pool), 0004 (device enrollment); crates/citadel-proto/src/{envelope.rs,delivery.rs}; AGENTS.md M2 sequencing (Opus citadel-core, K3 delivery transport + WS gateway + F2/F4 harness)

## Context

M1 is closed: identity, KT, auth, enrollment, and the 3×2 exit AC are green on
main. M2 delivers **encrypted DMs**: `delivery-service` grows a message path +
WS gateway; `citadel-core` gains OpenMLS group create/join/send/receive, padding,
and a local encrypted store; the harness runs F2 + F4 end-to-end between 3
clients (PLAN §9 M2).

Nothing in M2's wire model exists yet. This ADR is the design gate: it pins the
delivery wire contracts, the ciphertext-only storage schema, the two scoping
traps (franking, padding), the client store, and the named evidence tests —
before anyone writes service or core code, matching how ADR-0003/0004 gated M1.
It **adds** a `citadel-proto::delivery` module (this PR) and touches no existing
proto module, so auth/kt/credential/envelope on main are unchanged (AGENTS rule
5; Opus is sole proto merger). The reused `Envelope` (kind ∈
application/proposal/commit/welcome, base64 payload) already lives on main and is
the message carrier here.

The governing constraint throughout: the delivery service is **an untrusted
router and ciphertext store**. It may sequence and fan out opaque bytes; it may
never read, derive, or persist content or group secrets (INV-1), and it links no
decryption path. Every membership and ordering fact the server reports is a hint;
the client re-verifies it against MLS + the KT log (INV-3, INV-4).

## Decision

### 1. Delivery wire contracts (`citadel-proto::delivery`, added in this PR)

**seq vs epoch (the load-bearing framing).** The server cannot parse an MLS
message, so it cannot know an application message's epoch. Therefore:

- **`seq`** is **server-assigned**: authoritative, gap-free, monotonic *per
  group*. It is the only ordering the server owns and the cursor sync key.
- **`epoch`** is **client-declared** and **server-echoed** — an opaque ordering
  hint the server stores next to the row. It is never derived from ciphertext
  (INV-1) and never a trusted security value (INV-4). One-commit-per-epoch
  enforcement over the `commit` kind (INV-6) is **M3**, and will key off this
  same client-declared epoch under the per-group serialization point below; M2
  reserves it and does not enforce it.

**POST `/v1/groups/{gid}/messages`** — authenticated (bearer, ADR-0003 §3).
Body `SubmitMessageRequest { envelope, idempotency_key, recipient_device_ids }`:

- `envelope.payload_b64` = serialized OpenMLS `MlsMessageOut`. `envelope.seq`
  MUST be `None` (server assigns; else `invalid_request`). `envelope.epoch` =
  the client's current epoch (stored, echoed). `envelope.group_id` must equal
  the path `{gid}` (else `invalid_request`). `envelope.sender_device_id` is
  **ignored**; the server stamps the sender from the validated token — a
  client-claimed sender is never trusted.
- **Assignment + return.** The server takes the group's serialization point (a
  `groups.next_seq` counter bumped in the insert transaction, backed by
  `UNIQUE(mls_group_id, seq)`), inserts one `group_messages` row, and returns
  `SubmitMessageResponse { message_id, group_id, epoch (echoed), seq (assigned),
  server_ts }`.
- **Idempotency / dedup.** `idempotency_key` is a client UUID; `UNIQUE(mls_group_id,
  idempotency_key)`. A replay returns the **original** `(message_id, seq, epoch,
  server_ts)` with `200`, inserting nothing — safe offline-retry (F4 over a flaky
  link). This is the only dedup; the server does not hash payloads (it must not
  need to read them).

**GET `/v1/groups/{gid}/messages?after=<seq>`** — authenticated ciphertext sync.
`after` is the last `seq` the client holds (`0`/omitted = fresh sync). Returns
`MessagesPage { group_id, messages: Vec<Envelope>, next_after, has_more }`: rows
with `seq > after`, ascending, at most `MESSAGES_PAGE_LIMIT = 500`; each
`Envelope` has `seq`/`epoch`/`sender_device_id` populated.

- **Cursor semantics — decided: the cursor IS the seq, not an opaque blob.**
  `seq` is already server-authoritative, gap-free, and monotonic per group, and
  PLAN §6's client `sync_cursors(group_id, last_seq)` is keyed on exactly it. An
  opaque cursor buys nothing at M2 (single monotonic column) and adds
  encode/decode surface. Flagged for later: if a group's delivery is ever
  sharded across rows that are not globally seq-ordered (not in v1), revisit an
  opaque cursor then.

**WS `/v1/gateway`** — live fanout. Auth: `Authorization: Bearer <token>` on the
upgrade GET, validated exactly per ADR-0003 §3 (unexpired, not revoked, device
live); failure → `401` on the upgrade, no socket. After connect:

- **Frames.** `GatewayClientFrame::{Subscribe, Unsubscribe}{ group_ids }`;
  `GatewayServerFrame::{Subscribed, Message{ envelope }, Error{ code, message,
  group_id? }}`. JSON-framed, `type`-tagged (PLAN §4).
- **Sends go over REST, not the gateway.** A message is persisted + sequenced by
  `POST`, *then* fanned out over WS to subscribed devices. One sequencing/dedup
  home; the gateway is receive + subscription control only. Pinned so K3 does not
  build a second write path.
- **Subscription authorization is spam-hygiene, not confidentiality.** Fanning
  ciphertext to a non-member is harmless (INV-1: they cannot decrypt), and MLS
  membership is the client-verified authority (INV-4). A device may subscribe to
  group G iff the server's *delivery metadata* shows it as an addressee in G (has
  a welcome or a message addressed to it, or is a sender in G); others get an
  `Error` frame. This is never the security boundary.

**F2 Welcome addressing.** Welcomes target specific **devices** (the joiners are
not yet subscribed and have no group to sync), not a group broadcast:

1. Initiator fetches **one unconsumed KeyPackage per target device** via the M1
   `GET /v1/accounts/{id}/key-packages` (consuming, all-or-nothing across the
   account's active devices; ADR-0003 §4). Reused unchanged.
2. Initiator creates the MLS group, adds all target leaves in one commit,
   produces the Welcome, and submits it: `POST /v1/groups/{gid}/messages` with
   `envelope.kind == Welcome` and `recipient_device_ids = [target devices]`
   (required non-empty for Welcome; forbidden on other kinds —
   `SubmitMessageRequest::validate`).
3. The DS persists the Welcome as a `group_messages` row (ciphertext) **and**
   one addressing row per recipient in `welcome_deliveries(welcome_message_id,
   recipient_device_id, delivered_at NULL)`.
4. **Delivery + client verification (INV-4).** On a target device's next gateway
   connect, the DS pushes its undelivered welcomes as `Message` frames, then
   sets `delivered_at`. The client, before accepting the group, verifies the
   Welcome/GroupInfo signature and verifies **every member credential against
   the KT log** (identity has a verified KT inclusion proof AND the credential
   signature verifies under that identity — ADR-0001/0004 trust rule). Only then
   does it subscribe to `group_id` for ongoing fanout. First application message
   flows only after the initiator's client has verified commit acceptance (F2
   step 4).

The proto types for all of the above are in `crates/citadel-proto/src/delivery.rs`
(this PR): `SubmitMessageRequest`/`Response`, `MessagesPage`, `GatewayClientFrame`,
`GatewayServerFrame`, `MESSAGES_PAGE_LIMIT`.

### 2. Server storage = ciphertext only (INV-1)

Delivery tables hold opaque MLS bytes + `(group_id, epoch, seq)` + addressing
metadata. No plaintext, no decryption path, no crypto-facade dependency beyond
what M1 already allows (verify/sha256/random; delivery needs *none* of the three
for the message path — it stores and forwards bytes). `delivery-service` must
**not** depend on `citadel-core` or any OpenMLS decrypt (CI crypto-confinement,
AGENTS rule 6).

```
groups(
  mls_group_id   UUID PRIMARY KEY,
  dm             BOOLEAN NOT NULL DEFAULT true,   -- M2 is DMs; channel_id null until M3
  channel_id     UUID NULL,
  next_seq       BIGINT NOT NULL DEFAULT 0,       -- per-group serialization point
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
)

group_messages(
  id                UUID PRIMARY KEY,             -- server-assigned MessageId
  mls_group_id      UUID NOT NULL REFERENCES groups(mls_group_id),
  seq               BIGINT NOT NULL,              -- server-assigned, monotonic per group
  epoch             BIGINT NOT NULL,              -- CLIENT-DECLARED hint, not trusted (INV-4)
  kind              TEXT   NOT NULL CHECK (kind IN ('application','proposal','commit','welcome')),
  sender_device_id  UUID   NULL,                  -- from the auth token, never client-claimed
  idempotency_key   UUID   NOT NULL,
  payload_bytes     BYTEA  NOT NULL,              -- opaque MLS bytes; ciphertext only (INV-1)
  server_ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(mls_group_id, seq),
  UNIQUE(mls_group_id, idempotency_key)
)

welcome_deliveries(
  welcome_message_id  UUID NOT NULL REFERENCES group_messages(id),
  recipient_device_id UUID NOT NULL,
  delivered_at        TIMESTAMPTZ NULL,
  PRIMARY KEY (welcome_message_id, recipient_device_id)
)
```

- **Seq assignment** is one transaction: lock the `groups` row, `next_seq += 1`,
  insert with that seq; `UNIQUE(mls_group_id, seq)` is the backstop under
  concurrency. This same per-group serialization point is what M3 will use to
  enforce one-commit-per-epoch (INV-6) — reserved, not built here.
- **The no-plaintext canary (PLAN §13, INV-1) extends to these tables**, and this
  is an M2 exit requirement, not a future item. The harness injects canary
  strings through the F4 send path; the CI canary-scan job scans
  `group_messages.payload_bytes`, `welcome_deliveries`, and all delivery-service
  logs for them on every run. `payload_bytes` is MLS ciphertext, so a canary can
  only appear there if a client path leaked plaintext into the ciphertext-only
  channel — exactly the regression the scan must catch.

### 3. Two scoping calls (both are traps — pinned explicitly)

**FRANKING — decided: scoped OUT of the M2 delivery path.** F4 step 1 references a
franking tag + server countersignature, but `docs/protocol/franking.md` (the
commitment scheme, countersignature, verification algorithm) is an **M6**
prerequisite (PLAN §9 M6, §7 F6). M2 therefore ships **no** franking on the wire
and **no** server countersignature endpoint: there is no `franking` field in
`citadel-proto::delivery`, `delivery-service` never countersigns, and the F4 M2
test exercises send/receive/padding/local-store with **zero** franking
dependency. The no-plaintext AC does not depend on any franking code. Building a
tag now would mean inventing the HMAC-commitment scheme ahead of its spec — a
from-scratch construction the milestone ordering exists to prevent, and an INV-8
/ INV-10 risk. citadel-core's local `messages` row keeps a nullable `frank_tag`
column (NULL in M2) so M6 is a purely additive change, but nothing server-side or
in citadel-proto references franking in M2. **charge: confirm this scoping** (the
alternative — a reserved empty wire field + a countersign stub now — is rejected
below).

**PADDING BUCKETS — recorded: application-layer framing, not a crypto primitive
(INV-10 satisfied).** Bucket padding is deterministic, keyless length-hiding
framing done in **citadel-core**, applied to the plaintext **before** OpenMLS
encrypt and stripped **after** OpenMLS decrypt (pad-then-encrypt, so the server
sees only ciphertext in uniform length classes). It uses no key, KDF, nonce, or
MAC — it is not a primitive, so it does not violate INV-10's "no custom padding
scheme" (which forbids inventing padding *inside* the crypto layer; OpenMLS still
owns all AEAD).

- **Bucket set (pinned):** `{256, 1024, 4096, 16384}` bytes (PLAN §7 F4).
- **Frame layout:** `u32-BE content_length || content || zero-pad up to the
  smallest bucket ≥ (4 + content_length)`.
- **Location:** `citadel-core` framing module; `pad()` before encrypt, `unpad()`
  after decrypt (reads the length prefix, truncates, and asserts the pad bytes
  are zero).
- **Oversize rule:** if `4 + content_length > 16384`, reject at the client. M2
  handles text DMs; large payloads are attachments (M5), which carry their own
  keys in-band. No fifth bucket in v1.

### 4. Local encrypted store (client, citadel-core)

The only place plaintext exists (PLAN §3). SQLite via sqlx, whole-DB encrypted at
rest with a key in the OS keychain (INV-2), reusing M1's keychain integration.

```
conversations(group_id PRIMARY KEY, kind TEXT, title_local TEXT, created_at)
messages(local_id PRIMARY KEY, group_id, seq, epoch, sender_device_id,
         sent_ts, plaintext, frank_tag NULL,        -- frank_tag reserved for M6
         UNIQUE(group_id, seq))                      -- dedup on re-sync
sync_cursors(group_id PRIMARY KEY, last_seq)          -- mirrors server seq (§1)
pending_outbox(local_id PRIMARY KEY, group_id, idempotency_key,
               envelope_bytes, created_at)            -- offline send / idempotent retry
mls_state   -- OpenMLS storage-trait tables (encrypted at rest with the DB)
```

- **At-rest key (INV-2/INV-9/INV-10):** a 32-byte DB key from the OS CSPRNG via
  the crypto provider, generated on first run, stored in the OS keychain, and
  used to open the encrypted SQLite. Encryption uses an established SQLite-at-rest
  mechanism (SQLCipher-style), **not** a hand-rolled cipher — INV-10 holds. The
  key never serializes to any network call (INV-2).
- `plaintext` holds decrypted content and never leaves the device (PLAN §3).
  `pending_outbox.idempotency_key` is the same UUID sent to the server (§1), so a
  retry after a crash dedups server-side.

### 5. Adversarial test (PLAN §10, ≥1 per milestone)

The harness plays a **dishonest DS/AS** and clients must reject. The
milestone-minimum case (F2-specific, INV-4):

- **`adversarial_ds_swapped_keypackage_rejected`** — for a target device the
  dishonest server serves a KeyPackage whose credential does **not** chain to a
  KT-attested identity (no verified inclusion proof, or a credential signature
  that does not verify under the KT-logged identity key). The initiator, verifying
  every member credential against the KT log before finalizing the group (INV-4),
  rejects it and aborts DM creation. No group is created; no plaintext is sent.

Two further adversarial cases named for the M2 suite:

- **`adversarial_ds_replayed_welcome_rejected`** — the DS re-delivers a
  previously consumed / stale-epoch Welcome; the client rejects it (MLS
  epoch/ratchet check), joins nothing new.
- **`adversarial_ds_forged_commit_rejected`** — the DS injects a commit not
  signed by a group member; recipients' MLS validation rejects it and group state
  is unchanged (INV-3, INV-4).

## Alternatives considered

1. **Opaque cursor instead of raw seq.** Rejected for M2: `seq` is already
   authoritative/gap-free/monotonic and is the client's `sync_cursors` key; an
   opaque cursor is encode/decode surface with no M2 benefit. Revisit only if
   per-group delivery is ever sharded off a single seq column (post-v1).
2. **Send messages over the WS gateway.** Rejected: two write paths would mean two
   places assigning seq and enforcing idempotency. REST-submit-then-fanout keeps
   one durable, sequenced, dedup'd home; the gateway pushes.
3. **Reserved-but-empty franking wire field + a countersign stub now.** Rejected
   in favor of full scope-out (§3): a stub still forces an early guess at the
   commitment/countersign shape that M6's `franking.md` is meant to decide, and it
   makes the F4 test and no-plaintext AC silently depend on unbuilt code — the
   exact trap. citadel-core's nullable `frank_tag` column keeps M6 additive
   without any M2 wire commitment.
4. **Server derives/validates epoch or membership.** Rejected: the server cannot
   parse MLS (INV-1) and must not be the membership authority (INV-3/INV-4). Epoch
   is a stored client hint; membership is client-verified against MLS + KT.
5. **Trust `envelope.sender_device_id` from the client.** Rejected: the sender is
   stamped from the validated token; a client-claimed sender is spoofable.

## Consequences

- **Positive:** the delivery service stays a pure ciphertext router — sequence,
  store, fan out — with no crypto-facade dependency on the message path and no
  decryption link (INV-1 by construction). K3 can build delivery transport + the
  gateway directly against the pinned `citadel-proto::delivery` contracts while
  Opus builds the citadel-core MLS path in parallel. Idempotency makes F4 safe
  over flaky links. Franking and one-commit-per-epoch are cleanly deferred
  (M6/M3) with reserved seams, not silent dependencies.
- **Negative:** `epoch` on the wire is an untrusted hint, so any server-side use
  of it (M3 ordering) must re-derive trust from client-committed MLS state, never
  from the stored number. Subscription authorization is metadata-only (acceptable:
  INV-1 makes over-fanout harmless). Whole-DB SQLite-at-rest depends on a
  vetted mechanism (SQLCipher-style) being available to the desktop build — a
  dependency choice Opus/Grok confirm during build; if none is acceptable, that is
  an escalation, not a hand-rolled cipher.
- **Follow-ups:** M3 enforces one-commit-per-epoch (INV-6) over the `commit` kind
  at the per-group serialization point defined here, and adds
  `UNIQUE(mls_group_id, epoch) WHERE kind='commit'`; M5 adds attachments (oversize
  path) and offline catch-up scale; M6 adds franking (the reserved `frank_tag` +
  server countersignature + `franking.md`); M8 adds delivery/gateway rate limits
  alongside the ADR-0003 §7 surfaces.

## Evidence

Named tests that prove compliance. All db/harness tests run against real
PostgreSQL 16 in CI (`#[ignore]` + loud `DATABASE_URL`, never a mock; PLAN §13).
Ownership: harness/transport tests K3 (Opus blocking-review of the security
surface); citadel-core MLS/padding/store tests Opus; adversarial suite Opus
(`test-harness/adversarial`).

- **`f2_three_client_dm_creation`** — 3 clients; initiator fetches one KeyPackage
  per target device (consuming), creates the group, submits the Welcome addressed
  to the target devices; each target joins on next gateway connect, verifies
  GroupInfo + **every member credential against the KT log** (INV-4); all three
  converge on identical group membership.
- **`f4_send_receive_roundtrip`** — initiator sends an application message (padded
  to a bucket) via `POST`; the DS assigns `(epoch echoed, seq)`; both recipients
  receive it via WS fanout and via `GET ?after=` sync, decrypt, unpad, and store
  plaintext locally; the wire carries only ciphertext.
- **`submit_is_idempotent_and_seq_monotonic`** — replaying a submit with the same
  `idempotency_key` returns the same `seq` and inserts exactly one row; concurrent
  submits to one group receive gap-free monotonic seq (db-test + proptest).
- **`no_plaintext_scan_delivery_tables`** — canary injected through the F4 send
  path; the CI canary-scan finds zero hits in `group_messages.payload_bytes`,
  `welcome_deliveries`, and delivery-service logs (extends the M1 canary AC to M2
  tables; INV-1).
- **`device_compromise_past_messages_unreadable_fs`** — capture a device's MLS
  state, advance the group, wipe the pre-advance secrets; the captured snapshot
  cannot decrypt the post-wipe messages (forward secrecy; PLAN §9 M2 AC).
- **`pcs_recover_after_update`** — after a simulated compromise, a member performs
  an MLS self-update (commit) rotating its leaf; subsequent messages are secure
  again (post-compromise security; PLAN §9 M2 AC).
- **`padding_bucket_roundtrip_and_sizes`** (proptest, citadel-core) — `pad`/`unpad`
  is lossless for any content length ≤ 16380, and every padded length is exactly
  one of `{256, 1024, 4096, 16384}`; oversize rejects.
- **Adversarial (§5):** `adversarial_ds_swapped_keypackage_rejected` (milestone
  minimum), plus `adversarial_ds_replayed_welcome_rejected` and
  `adversarial_ds_forged_commit_rejected`.

## Open decisions for charge

1. **Franking scope (§3, primary).** Confirm franking is scoped **out** of the M2
   delivery path (no wire field, no server countersignature; F4 M2 test has zero
   franking; citadel-core keeps a nullable `frank_tag` for M6). Recommendation:
   yes — the alternative reverses the M6-first ordering and creates the silent
   dependency the trap warns about.
2. **Padding as application framing (§3).** Confirm the `{256,1024,4096,16384}`
   bucket set, the `u32-BE len || content || zero-pad` layout, pad-then-encrypt in
   citadel-core, and reject-over-16KB (attachments = M5). This is the reading of
   INV-10 that makes bucket padding legal (framing, not a primitive) — confirm it.
3. **Cursor = raw seq, not an opaque blob (§1).** Confirm. Cheapest correct choice
   at M2; opaque cursor deferred to if/when delivery is sharded (post-v1).
4. **Sends over REST only, gateway is receive/subscribe (§1).** Confirm the single
   write path (no message-send frame on the gateway).
5. **Subscription authorization = spam-hygiene, not confidentiality (§1).** Confirm
   that over-fanout of ciphertext to a non-member is acceptable (INV-1), so the
   gateway's subscribe check is metadata-only and never the security boundary.
