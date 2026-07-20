# ADR-0004: Device enrollment parameters (POST /v1/devices)

- **Status:** PROPOSED
- **Date:** 2026-07-19
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3.
- **Invariants touched:** INV-2 (services hold no user keys), INV-4 (clients
  verify credentials against KT), INV-9 (device-key challenge randomness, reused
  from ADR-0003 §1), INV-10 (serialization, not primitives)
- **Related:** plans/PLAN.md §7 F1 (additional-device flow), §8 (`POST /devices`);
  docs/decisions/0001 (KT log), 0002 (crypto facade), 0003 (auth-flow params);
  crates/citadel-proto/src/{auth.rs,credential.rs}; docs/protocol/auth.md;
  the M1 exit AC (3 accounts × 2 devices)

## Context

`POST /v1/devices` is the one M1 endpoint still unbuilt: it had no parameter
spec, so it was correctly left out of ADR-0003 (challenge/registration/pool) and
scoped away. The M1 exit AC needs **3 accounts × 2 devices**, which requires
enrolling a second device per account. This ADR pins the smallest parameter set
that implements PLAN.md §7 F1's additional-device step, reusing ADR-0003's
machinery and the credential/endorsement contracts already in `citadel-proto`.

PLAN.md §7 F1 fixes the shape: registration "appends the identity key to the KT
log"; the additional-device path is "**existing device signs the new device's
credential**; new device uploads KeyPackages." The wire contracts already exist
on main and are unchanged by this ADR:

- `EnrollDeviceRequest { credential: DeviceCredential, endorsement: DeviceEndorsement }`
- `EnrollDeviceResponse { device_id }`
- `DeviceCredential` = `DeviceCredentialTbs { account_id, device_id, identity_pubkey, device_pubkey, issued_at }` + an Ed25519 signature **by the account identity key** over `DeviceCredentialTbs::signing_input()` (domain `citadel/v1/device-credential`).
- `DeviceEndorsement { endorsing_device_id, signature }` = an Ed25519 signature **by an existing device key** over `endorsement_signing_input(&credential)` (domain `citadel/v1/device-endorsement`, which commits to the new credential's full TBS **and** its identity signature).

So the cryptographic proofs are already designed; this ADR decides only *how the
server authorizes and verifies an enrollment*, and *what it does and does not
persist*.

## Decision

`POST /v1/devices` — **authenticated** (a session already exists, unlike
registration). Body: `EnrollDeviceRequest`. The server accepts iff **all** hold;
any signature failure collapses to `unauthorized` (ADR-0003 §1 pattern):

1. **Existing-account authorization = bearer token + endorsement, same device.**
   - `Authorization: Bearer <token>` is validated exactly per ADR-0003 §3
     (`validate_token`): unexpired, not revoked, device not revoked. Missing /
     invalid / expired / revoked → `unauthorized` (401). This proves a **live,
     unrevoked** existing device is calling and yields its `device_id` and
     `account_id` — no new mechanism, no per-request key material (INV-2).
   - The endorsement must be by that same device: `endorsement.endorsing_device_id
     == token.device_id`, else `forbidden` (403). The server loads the endorsing
     device's `device_pubkey` and verifies `endorsement.signature` over
     `endorsement_signing_input(&credential)` via the facade (ADR-0002). This is
     the decisive check: a **stolen token alone cannot enroll** (the attacker
     cannot produce the endorsing device's signature), and the endorsement is
     bound to the exact new-credential bytes (replay to enroll a *different*
     device is impossible).
2. **Account binding.** `credential.tbs.account_id` must equal the token
   device's account, else `forbidden` (403) — a device enrolls only for its own
   account.
3. **New-credential verification (what clients will trust, INV-4).**
   - `credential.tbs.identity_pubkey` must equal the account's stored
     `identity_pubkey`; mismatch → `unauthorized`. A device cannot be bound to a
     different identity than the one the KT log already attests.
   - `credential.signature` must verify under `credential.tbs.identity_pubkey`
     over `credential.tbs.signing_input()` via the facade → the **account
     identity key** authorized this device binding (PLAN §8: "signed by identity
     key").
4. **New-device proof-of-possession is deferred, by design.** Enrollment only
   *binds* `device_pubkey`; it does **not** require the new device to sign
   anything. Possession of the new device key is proven the first time that
   device runs the ADR-0003 §1 challenge-response to obtain its own token — a key
   the enroller does not actually hold is inert (it can never authenticate,
   publish, or act). This mirrors registration, where the first device also
   proves possession only at its first challenge-response, and it avoids a proto
   change for no security gain.
5. **Persistence = one INSERT, no KT append.** On success the server inserts one
   `devices` row (`id = credential.tbs.device_id`, `account_id`, `device_pubkey`,
   `credential` = the canonical signed wire bytes) with `ON CONFLICT (id) DO
   NOTHING`; `rows_affected != 1` → `conflict` (409). Returns
   `EnrollDeviceResponse { device_id }`. **Enrollment does not touch the KT log**
   — see §"KT log" below. Because there is no KT append, enrollment does not take
   the log mutex and is cheaper than registration.

After enrollment the new device uses the **existing** endpoints unchanged:
ADR-0003 §1 challenge-response to get a token, then `POST
/v1/devices/{id}/key-packages` to publish its pool (F1 step 4). Enrollment is
deliberately thin.

**No proto change is required.** All request/response/credential/endorsement
types and signing inputs already exist on main.

### KT log: no per-device leaf in M1 (the load-bearing call)

The KT log attests **account identity keys**, one leaf per account, appended at
registration (`KtLeaf { account_id, handle, identity_pubkey, appended_at }` —
PLAN §7 F1 step 2). A second device shares the account's identity key, and
`KtLeaf` has **no device field**, so:

- appending a leaf at enrollment would write a *duplicate identity leaf*
  (same `account_id` + `identity_pubkey`, new `appended_at`) that attests nothing
  about the device — pure log growth with no transparency value; and
- clients already establish device trust without it (INV-4): a device credential
  is trusted iff the account's `identity_pubkey` has a verified KT inclusion proof
  **and** the credential's identity signature verifies under it. The identity is
  logged once; devices chain to it by signature.

This matches PLAN.md §7 F1, whose additional-device path logs nothing (the "new
leaf" there is the MLS *group* leaf, not a KT leaf). It also keeps the M1 exit
AC coherent: the harness verifies **3** account-identity inclusion proofs (one
per account), and enrollment leaves `tree_size` unchanged.

**Flagged for charge (proto change if desired, explicitly out of M1 scope):**
true *device transparency* — letting a client detect a rogue device silently
added under a compromised identity key by enumerating the log — is a real,
valuable property this design does **not** provide. It would require extending
`KtLeaf` (or adding a device-leaf variant) to carry `device_id`/`device_pubkey`,
i.e. a `citadel-proto` change and a leaf-encoding ADR, plus a KT append in the
enrollment transaction. Deferred beyond M1 as a named residual gap; recommend
against pulling it into M1 (gold-plating the exit AC). If charge wants it now,
that reverses §5's "no KT append" and adds the proto work — say so and I own the
proto PR.

## Alternatives considered

1. **Endorsement-only, no bearer token** (verify the endorsement signature and a
   `devices.revoked_at IS NULL` lookup, skip the token). Smaller, and the
   device-key signature is cryptographically stronger than a bearer token. Chosen
   *against* only narrowly: requiring the token reuses ADR-0003 §3 wholesale
   (revocation freshness for free), gives a uniform authenticated write surface
   consistent with the pool endpoints, and yields a clean rate-limit hook for M8.
   The token is cheap for the client (an existing device already holds one). Both
   together = possession of a valid session **and** the device key.
2. **Require a new-device self-signature at enrollment (explicit PoP).** Would
   need a new signature field in `EnrollDeviceRequest` → a proto change, for a
   property already enforced at first challenge-response (§4). Rejected as churn
   without security gain.
3. **Append a per-device KT leaf now.** Either a redundant identity leaf (no
   value) or a `KtLeaf` proto extension (real device transparency, but M1
   gold-plating). Deferred — see §"KT log".
4. **Unauthenticated enrollment guarded only by the identity signature.** Drops
   the "live existing device authorized this" property and re-opens an
   unauthenticated write; rejected.

## Consequences

- Positive: enrollment is a thin, authenticated endpoint reusing
  `validate_token`, the facade, and the existing credential/endorsement
  contracts; **no proto change**; no KT-log contention; buildable in hours.
  Enrolling a device requires *both* a live existing-device session and that
  device's key, *and* the account identity key's signature — three independent
  secrets.
- Negative: no device transparency in M1 (flagged above); enrollment presumes the
  account identity private key is available to sign the new credential (the
  primary device or a recovery secret holds it — consistent with PLAN's
  identity-signed credentials; account recovery remains out of scope, PLAN §8).
- Follow-ups: M8 rate limiting covers this endpoint alongside the ADR-0003 §7
  surfaces; device transparency + `KtLeaf` extension is a candidate later ADR if
  charge wants log-visible device additions; device *revocation* UX,
  cross-signing ceremonies, and recovery are explicitly out of M1 scope.

## Evidence

Named tests (auth-service, Opus blocking-review; all against real PostgreSQL 16
in the CI `db-tests` job, `#[ignore]` + loud `DATABASE_URL`, never a mock):

- `enroll_second_device_succeeds_then_authenticates` — register account + device
  A, get A's token; enroll device B (identity-signed credential + A's endorsement
  + A's bearer token); B then completes ADR-0003 §1 challenge-response and obtains
  its own token; both devices are active for the account.
- `enroll_requires_valid_bearer_token` — absent / expired / revoked token →
  `unauthorized`; no `devices` row is created.
- `enroll_rejects_bad_identity_signature` — a credential whose signature is not by
  the account identity key → `unauthorized`; no row created.
- `enroll_rejects_identity_pubkey_mismatch` — `credential.tbs.identity_pubkey` ≠
  the account's stored identity → `unauthorized` (cannot bind a device to another
  identity).
- `enroll_rejects_foreign_or_mismatched_endorsement` — endorsement by a device of
  another account, or `endorsing_device_id != token.device_id`, or an invalid
  endorsement signature → `forbidden`/`unauthorized`; no row created.
- `enroll_rejects_duplicate_device_id` — replay of a completed enrollment →
  `conflict` (409); exactly one `devices` row exists for that id.
- `enroll_does_not_grow_kt_log` — `GET /v1/kt/tree-head` reports the same
  `tree_size` before and after a successful enrollment (§"KT log": no append).
