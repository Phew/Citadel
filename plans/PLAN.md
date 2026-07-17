# Citadel: Agent Implementation Plan

Working name: **Citadel** (placeholder, trivially renameable; grep for `citadel-app`).
Purpose: a Discord-style community chat platform with Signal-level end-to-end encryption. The server is an untrusted router and blob store. It must never be able to read message content, voice, or video.

This document is the source of truth for an autonomous coding agent. Read it fully before writing code. Work milestone by milestone, in order. Do not skip acceptance criteria. When a decision is not specified here, choose the simplest option that does not violate a Security Invariant, and record the decision in `docs/decisions/` as an ADR.

---

## 1. Goals and Non-Goals

### Goals (v1)
- Servers ("houses") containing text channels and voice channels
- All text messages E2E encrypted via MLS (RFC 9420), one MLS group per channel
- Encrypted 1:1 and small-group DMs
- Forward secrecy and post-compromise security for all content
- Multi-device support (each device is an MLS leaf)
- Signed roles/permissions validated by clients, not asserted by the server
- Cryptographically verifiable abuse reporting (message franking)
- Voice channels E2E encrypted following the DAVE pattern (MLS-derived per-sender frame keys, untrusted SFU)
- Key transparency log for identity keys

### Non-Goals (v1)
- Federation
- Metadata privacy beyond minimization (no sealed sender in v1)
- Server-side search of any kind (search is client-side over local plaintext)
- Message history for members prior to their join epoch
- Stage channels / broadcasts to thousands of listeners
- Mobile clients (v1 targets desktop; core is portable Rust so mobile comes later)

---

## 2. Security Invariants (HARD RULES)

The agent must treat these as inviolable. Any task, refactor, or "fix" that breaks one of these is wrong even if tests pass.

- **INV-1: No plaintext server-side.** No server component may ever receive, log, persist, or process plaintext message content, media frames, attachment bytes, or MLS group secrets. Server code must not link against decryption paths for application messages.
- **INV-2: Keys never leave the client.** Private keys (identity, device, MLS leaf secrets, epoch secrets) are generated on-device and never serialized to any network call. Key export exists only for local encrypted backup.
- **INV-3: The server can propose, never decide.** The server may act as an MLS external sender to propose adds/removes (joins, bans, expired devices). Membership changes take effect only when a member client commits and other clients validate the commit.
- **INV-4: Clients validate everything.** Every commit, proposal, welcome, credential, and role assertion is cryptographically verified client-side. The server's word is never trusted for group state, membership, or roles.
- **INV-5: No silent downgrade.** There is no unencrypted fallback for text or voice. Version negotiation may reject a session; it may never quietly deliver plaintext.
- **INV-6: Deterministic commit ordering.** Exactly one commit succeeds per group per epoch. The Delivery Service enforces linear epoch ordering; conflicting commits are rejected with the canonical state, and clients must handle rejection by rebasing.
- **INV-7: Roles are signed data.** Permission checks that matter (who can post, kick, invite) are enforced by clients against signed role state in the MLS GroupContext extension. Server-side checks exist only as spam/rate-limit hygiene, never as the security boundary.
- **INV-8: Franking, not scanning.** Abuse handling is via recipient reports carrying cryptographic proof (franking tags). No server-side content scanning hooks may be added, even "temporarily."
- **INV-9: All randomness from the OS CSPRNG** via the crypto provider. Never `rand::thread_rng` for key material; use the OpenMLS crypto provider's RNG.
- **INV-10: No crypto primitives from scratch.** Use OpenMLS for group crypto, its ciphersuite providers for primitives. Writing a custom KDF, padding scheme, or nonce scheme is forbidden.

---

## 3. System Architecture

```
+--------------------------------------------------------------+
|                        CLIENTS                               |
|  citadel-core (Rust): MLS state, crypto, sync, local store     |
|  citadel-desktop (Tauri + React): UI over citadel-core via FFI   |
+--------------------------------------------------------------+
        |  HTTPS (REST)            |  WebSocket (fanout)
        v                          v
+--------------------------------------------------------------+
|                        BACKEND (Rust)                        |
|                                                              |
|  auth-service (AS)      delivery-service (DS)     blobstore  |
|  - accounts             - per-group commit        - E2EE     |
|  - device creds           sequencing                attach-  |
|  - KeyPackage pool      - message fanout            ments    |
|  - key transparency     - external sender                    |
|    log                    proposals                          |
|                                                              |
|  directory-service              sfu-gateway (M7)             |
|  - houses, channels, invites    - encrypted frame routing    |
|  - signed role state blobs      - MLS DS for voice sessions  |
+--------------------------------------------------------------+
        |
        v
   PostgreSQL (ciphertext blobs, directory state, KT log)
   Object storage (encrypted attachments)
```

Component responsibilities:

- **auth-service.** Account registration, device enrollment, credential issuance, KeyPackage publish/fetch (one-time-use pool per device), append-only key transparency (KT) log with signed tree heads.
- **delivery-service.** The MLS Delivery Service. Accepts MLS messages, enforces one-commit-per-epoch ordering per group, fans out via WebSocket, stores ciphertext for offline devices. Acts as external sender to propose membership changes triggered by directory events (join approved, ban issued).
- **directory-service.** Houses, channel lists, invite links, membership rosters, role definitions. All role state it stores is an opaque signed blob produced by clients; the service orders and distributes it but cannot forge it (INV-7).
- **blobstore.** Attachments encrypted client-side with per-attachment keys distributed inside MLS application messages. Server sees random bytes plus size.
- **citadel-core.** The only place plaintext exists. Owns OpenMLS state, local SQLite (encrypted at rest via key in OS keychain), message franking, sync cursors, and exposes a typed API to UIs.

---

## 4. Technology Stack (fixed; do not substitute without an ADR)

| Layer | Choice | Notes |
|---|---|---|
| Group crypto | OpenMLS (latest stable) | RFC 9420. Use `openmls`, `openmls_rust_crypto` provider |
| Ciphersuite | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | Default; single suite in v1 |
| Backend | Rust, axum, tokio, sqlx, PostgreSQL 16 | One workspace, multiple service crates |
| Realtime | WebSocket (axum), JSON-framed envelope with base64 MLS payloads | Move to binary framing later if needed |
| Client core | Rust crate `citadel-core`, exposed via Tauri commands | Same crate later reused for mobile via UniFFI |
| Desktop UI | Tauri 2 + React + TypeScript + Tailwind | |
| Local store | SQLite via sqlx, encrypted DB key in OS keychain | |
| Attachments | S3-compatible API (MinIO in dev) | |
| Voice (M7) | LiveKit-style SFU or minimal custom SFU; client-side frame encryption via WebRTC encoded transforms, keys exported from the channel MLS group (DAVE pattern) | Study daveprotocol.com first |
| CI | GitHub Actions: fmt, clippy (deny warnings), test, cargo-audit, cargo-deny | |

---

## 5. Repository Layout (monorepo)

```
epoch/
  Cargo.toml                 # workspace
  crates/
    citadel-proto/             # shared types, envelope formats, error codes
    citadel-core/              # client core: MLS state machine, sync, franking
    auth-service/
    delivery-service/
    directory-service/
    blobstore-service/
    kt-log/                  # key transparency lib used by auth-service
    test-harness/            # multi-client integration test utilities
  apps/
    desktop/                 # Tauri + React
  docs/
    decisions/               # ADRs, numbered
    protocol/                # flow specs kept in sync with code
  deploy/
    docker-compose.yml       # postgres, minio, all services
  PLAN.md                    # this file
```

---

## 6. Core Data Model

### Server-side (PostgreSQL). Everything content-bearing is ciphertext.

```
accounts(id, handle, identity_pubkey, created_at, status)
devices(id, account_id, device_pubkey, credential, created_at, revoked_at)
key_packages(id, device_id, package_bytes, consumed_at)        -- one-time pool
kt_log(seq, leaf_hash, tree_head, signature, timestamp)        -- append-only

houses(id, name_ct, owner_account_id, created_at)              -- name encrypted optional v1: plaintext name acceptable, ADR it
channels(id, house_id, kind[text|voice], mls_group_id, position)
house_members(house_id, account_id, joined_at, banned_at)
role_state(house_id, seq, signed_blob, author_device_id)       -- opaque, client-signed
invites(code, house_id, created_by, expires_at, max_uses, uses)

groups(mls_group_id, channel_id?, dm?, current_epoch, created_at)
group_messages(id, mls_group_id, epoch, seq, kind[app|proposal|commit|welcome],
               sender_device_id, payload_bytes, server_ts)
  -- UNIQUE(mls_group_id, epoch, kind='commit') enforced transactionally (INV-6)

attachments(id, blob_key, size, uploader_device_id, created_at) -- bytes in object store
reports(id, reporter_account_id, message_ref, franking_proof, submitted_at, status)
```

### Client-side (SQLite, encrypted)

```
mls_state            -- OpenMLS provider storage (use OpenMLS storage traits)
conversations(group_id, kind, house_id?, channel_id?, title)
messages(local_id, group_id, epoch, seq, sender, sent_ts, plaintext, frank_tag)
pending_outbox(...)  -- for offline send
sync_cursors(group_id, last_seq)
contacts(account_id, handle, identity_pubkey, verified_at?)   -- safety-number state
```

---

## 7. Protocol Flows (implement exactly; each flow gets an integration test)

### F1. Registration and device enrollment
1. Client generates identity keypair (Ed25519) and first device keypair.
2. POST /v1/accounts with handle + identity pubkey; server creates account, appends identity key to KT log, returns signed tree head.
3. Client builds an MLS credential binding device key to identity key (basic credential in v1, signed by identity key).
4. Client generates N=100 KeyPackages, POST /v1/devices/{id}/key-packages.
5. Client stores identity + device keys in OS keychain; verifies its own KT inclusion proof.

Additional device: existing device signs the new device's credential; new device uploads KeyPackages; every group the account belongs to gets an Add proposal for the new leaf at next activity (lazy enrollment, tracked in outbox).

### F2. DM creation (2 to 8 members)
1. Initiator fetches one unconsumed KeyPackage per target device (server marks consumed).
2. Initiator creates MLS group, adds all leaves in one commit, sends Welcome via DS.
3. DS stores Welcome addressed to target devices; targets join on next connect, verify GroupInfo, verify each member credential against KT log.
4. First application message flows only after initiator's client verifies commit acceptance.

### F3. Channel join (house member enters a channel's group)
1. User accepts invite -> directory-service adds account to house_members and emits event.
2. DS (as external sender) sends Add proposal(s) for the user's devices, referencing fetched KeyPackages, into the channel group.
3. Any online member client (deterministic election: lowest leaf index among online moderators, fallback any member) issues the Commit including pending proposals.
4. New member receives Welcome; history before this epoch is invisible by design.

### F4. Message send
1. citadel-core encrypts application message (padded to bucket sizes: 256B/1KB/4KB/16KB) with franking tag computed per the franking spec in docs/protocol/franking.md (HMAC commitment scheme; server countersigns delivery).
2. POST to DS; DS assigns (epoch, seq), countersigns franking commitment, fans out.
3. Recipients decrypt, verify franking tag, store plaintext locally only.

### F5. Ban
1. Moderator client verifies its own role from signed role_state, issues Remove proposals for all target leaves plus a role_state update, commits.
2. Directory-service marks banned (metadata hygiene). Clients treat the MLS Remove as authoritative (INV-3, INV-7).

### F6. Report
1. Recipient submits plaintext + franking opening + server countersignature to POST /v1/reports.
2. Server verifies the franking proof chain and only then can it read that single message. Verification failure = reject. Document the exact scheme before coding (docs/protocol/franking.md is a prerequisite task in M6).

### F7. Commit conflict
1. Two clients race to commit in epoch E. DS accepts the first transactionally, rejects the second with 409 + canonical commit.
2. Losing client merges: processes winning commit, re-derives state, re-issues its proposals in epoch E+1. Test this explicitly with 10 racing clients.

---

## 8. API Surface (v1, prefix /v1)

Auth: bearer tokens from device-key challenge-response (POST /v1/auth/challenge, /v1/auth/verify). No passwords in v1; account recovery is out of scope (document as known limitation).

```
POST   /accounts                      register
GET    /kt/tree-head                  latest signed tree head
GET    /kt/proof?leaf=...             inclusion proof
POST   /devices                       enroll device (signed by identity key)
POST   /devices/{id}/key-packages     replenish pool
GET    /accounts/{id}/key-packages    fetch one per device (consuming)

POST   /houses                        create
POST   /houses/{id}/invites           create invite
POST   /invites/{code}/accept         join house
GET    /houses/{id}                   directory state + latest role_state blob
POST   /houses/{id}/role-state        append signed role blob

POST   /groups/{gid}/messages         send MLS message (app/proposal/commit/welcome)
GET    /groups/{gid}/messages?after=  ciphertext sync
WS     /gateway                       auth, subscribe groups, receive fanout

POST   /attachments                   presigned upload of ciphertext
POST   /reports                       franking report
```

---

## 9. Milestones

Each milestone lists tasks and acceptance criteria (AC). A milestone is done when all ACs pass in CI, including the multi-client integration tests in test-harness. Commit small, keep main green.

### M0: Scaffolding (agent starts here)
- Workspace, crates, docker-compose (postgres + minio), CI pipeline, citadel-proto envelope types, error taxonomy, ADR template.
- AC: `cargo test` green in CI; `docker compose up` boots all service stubs with health endpoints.

### M1: Identity and KT
- auth-service: accounts, devices, KeyPackage pool; kt-log append-only Merkle log, signed tree heads, inclusion proofs; citadel-core keychain integration.
- AC: harness registers 3 accounts, 2 devices each; KT inclusion proofs verify; consuming the same KeyPackage twice is impossible under concurrent load (property test).

### M2: Encrypted DMs
- delivery-service message path + WS gateway; citadel-core group create/join/send/receive over OpenMLS; local encrypted SQLite store; padding buckets.
- AC: harness runs F2 + F4 end to end between 3 clients; server DB provably contains no plaintext (test greps ciphertext tables for known plaintext markers); device compromise simulation shows past messages unreadable (delete state, verify FS) and future messages recover after update (PCS test).

### M3: Channels and commit ordering
- One-commit-per-epoch enforcement; external-sender proposals; F3 join flow; F7 conflict handling; committer election.
- AC: 25-client channel, randomized join/leave storm for 500 epochs, all clients converge to identical group state hash; F7 race test with 10 concurrent committers never forks.

### M4: Houses, roles, moderation
- directory-service; invites; signed role_state in GroupContext extension; kick/ban (F5); client-side permission enforcement.
- AC: non-mod cannot produce an accepted Remove (clients reject, harness asserts); ban removes all target devices within one epoch; forged role blob from server is rejected by all clients.

### M5: Sync, multi-device, attachments
- Offline catch-up via sync cursors; lazy device enrollment across groups; encrypted attachments with in-band keys; outbox.
- AC: device offline for 1,000 messages catches up correctly; adding a device grants access to new messages in all groups within N=2 epochs of activity, and to no prior messages; attachment round-trip with server storing only ciphertext.

### M6: Franking and reports
- Write docs/protocol/franking.md first (commitment scheme, server countersignature, verification algorithm), then implement.
- AC: valid report verifies and reveals exactly one message; tampered report rejected; server cannot decrypt any unreported message (negative test).

### M7: Voice (DAVE pattern)
- SFU that routes opaque frames; client WebRTC encoded transforms; per-sender frame keys exported from channel MLS group; key rotation on join/leave.
- AC: 5-client call, joiner cannot decrypt pre-join frames (capture + replay test), leaver cannot decrypt post-leave frames; SFU code contains no frame decryption path.

### M8: Desktop UX hardening
- Safety-number verification UI, encryption state indicators, KT mismatch alerts, key backup (local, passphrase-encrypted), rename from working name if decided.
- AC: downgrade attempt (INV-5) surfaces a blocking error, never silent fallback; usability pass on join/verify flows.

---

## 10. Testing Strategy

- **Unit**: per-crate, standard.
- **Property tests** (proptest): KeyPackage consumption, commit ordering, padding buckets, KT log append-only property.
- **Multi-client integration** (test-harness): every F-flow, run in CI against dockerized services. This is the backbone; invest here.
- **Adversarial tests**: malicious-server suite where the harness plays a dishonest DS/AS (forged commits, replayed welcomes, swapped KeyPackages, forged role blobs, downgrade offers). Clients must reject every case. Add one adversarial test per milestone minimum.
- **No-plaintext audit test**: automated grep/scan of all server-side tables and logs for canary plaintext strings injected by the harness. Runs in CI forever.

## 11. Definition of Done (v1)

- All milestones' ACs green; adversarial suite green.
- `docs/protocol/` matches implementation (checked in M-final review).
- cargo-audit / cargo-deny clean; no `unsafe` outside vetted FFI boundaries.
- Threat model doc updated with known gaps (metadata, recovery, sealed sender) honestly listed.
- The one-sentence claim holds and is testable: "The operator of Citadel cannot read your messages, and we can demonstrate it."

## 12. Deferred / Open Questions (do not solve in v1; ADR when picked up)

- Account recovery without custodial keys (social recovery? passphrase escrow?)
- Sealed-sender-style metadata protection
- Mobile clients via UniFFI bindings
- Very large channels (>2,000 leaves): subgroup fanout or per-channel sharding
- History sharing for new members (explicit mod-initiated, off by default)
- Federation


## 13. Hard testing rules (learned the expensive way; CI-enforced)

- A test that cannot reach its required infrastructure (database, service, network) must FAIL loudly, never skip or return Ok. CI provisions the infrastructure; a green check must mean the property was actually exercised.
- The no-plaintext canary scan is an M1 exit requirement, not a future item: the harness injects canary strings through every client path and CI scans all server tables and logs for them on every run.
- Capability claims in PRs require reproducible evidence: a named test, a committed fixture, and an independent oracle where one exists (e.g. the Go oracle pattern for Merkle structures).
- Toolchain is pinned in rust-toolchain.toml; MSRV bumps happen only via ADR, never as a side effect of a dependency addition.
