# ADR-0009: The web client is a lower-trust tier, and what it stores

- **Status:** PROPOSED
- **Date:** 2026-09-06
- **Deciders:** charge (required for ACCEPTED); author: core
- **Invariants touched:** INV-1 (holds: the server still stores and routes ciphertext only), INV-2 (holds in letter — keys never leave the client — but the "client" is code the server delivered; that gap is this ADR's subject), INV-4 (holds: the wasm core verifies everything a native core does), INV-5 (holds: same wire-version refusal), INV-9 (browser entropy is `crypto.getRandomValues` via `getrandom/js`; docs/issues/016), INV-10 (same OpenMLS/RustCrypto chain compiled to wasm)
- **Related:** ADR-0008 (the shared core); ADR-0007 §2 and §6 (what "at rest" and "forward secrecy" mean for a native store, which this ADR does **not** claim for the browser); docs/issues/016; plans/PLAN.md §1 (v1 targets desktop), §3, §12

## Context

charge wants a browser client alongside the native apps (ADR-0008). A browser
client cannot be "as secure as Signal" and the reason is structural, not a
bug to fix later: **the server delivers the JavaScript and wasm that hold the
keys.** A compromised, coerced, or malicious server can serve a modified
client to one user, once, and nothing in MLS or key transparency detects it.
Signal does not ship a browser client for exactly this reason. Every other
property Citadel claims still holds in the browser: the server never sees
plaintext, the client verifies every credential against the KT log, there is
no unencrypted fallback. What changes is who you must trust to get honest
client code, and where secrets rest between sessions.

The second question is storage. ADR-0007's store is SQLCipher with a key in
the OS credential store. Neither exists in a browser: `rusqlite` does not
build for wasm32 (docs/issues/016 §3), and there is no OS credential store —
the nearest thing is a WebCrypto `CryptoKey` marked non-extractable, which
protects the key bytes from JavaScript but not the *use* of the key from any
JavaScript running in the same origin.

## Decision

1. **The web client is a labelled lower-trust tier.** Its UI renders a
   permanent, non-dismissable banner whose normative text is:

   > Web client: lower trust. The server delivers this code, so a compromised
   > server could serve you a modified client. Messages are still end-to-end
   > encrypted and the server cannot read them. For the strongest protection
   > use the native app.

   Wording may be edited for length; the three facts (server delivers the
   code; still end-to-end encrypted; native is stronger) may not be dropped.
   The banner is asserted by `banner_is_present_in_every_web_render`.

2. **Web devices are ordinary devices.** They register and enroll through F1,
   are KT-attested, are ordinary MLS leaves, publish KeyPackages, and receive
   Welcomes. Peers see a web device in a group's membership like any other
   device. Nothing in the protocol is weakened for the web; the tier is about
   code delivery and key residency only. (A future "device kind" field in the
   device credential, so peers can *see* that a leaf is a web device, is a
   follow-up, not part of this decision.)

3. **Storage tiers, one at a time.**
   - **W0 — session-only** (first milestone). MLS state and application rows
     live in `openmls_memory_storage::MemoryStorage` behind
     `citadel-app`'s `MlsStateStore` trait. Closing the tab ends the device:
     its signing seed and its groups are gone, and the next visit enrolls a
     **new** device. Consequences stated plainly: every visit adds a device
     leaf that peers must eventually remove (the M3 server-proposed removal
     path, INV-3, and a best-effort self-remove on `pagehide`); KeyPackages a
     W0 device publishes are bounded to a **1-hour lifetime** so the pool
     does not fill with packages for dead sessions. W0 exists to prove the
     wasm core end to end against the live stack; it is not the shipping web
     tier.
   - **W1 — durable encrypted blob** (second milestone, the shipping tier).
     The whole client state (the memory store's contents plus application
     rows) is serialized with the ADR-0007 §1 codec discipline and encrypted
     as **one blob** under AES-256-GCM with a **non-extractable WebCrypto
     `CryptoKey`** stored in IndexedDB; the blob is written through on every
     state-changing operation in a single IndexedDB transaction, which is the
     browser's version of ADR-0007 §5's one-transaction-per-operation. The
     device identity therefore survives across visits and the W0 device churn
     disappears. What W1 resists: another origin, a disk reader without the
     browser profile, and casual inspection. What it does **not** resist:
     JavaScript running in the same origin (XSS, a modified client) — which
     can use the key even though it cannot read it — or the server, per the
     tier statement. **ADR-0007 §6's forward-secrecy claim is not made for
     W1** until a test in the shape of `post_restart_snapshot_proves_mls_forward_secrecy`
     exists against the blob; until then the web tier claims only that the
     server holds ciphertext.
   - A SQLite-in-wasm engine (wa-sqlite, sql.js) with app-layer encryption
     is **rejected**: it is a second store implementation to audit, with none
     of SQLCipher's page authentication, and it buys nothing W1 lacks.

4. **Code-delivery hardening is required, and is not a substitute for the
   tier statement.** The web app ships with Subresource Integrity on every
   script, a Content Security Policy with no `unsafe-inline` and no remote
   script sources, `Strict-Transport-Security`, and a build that is
   reproducible from the tagged commit so a user *can* compare what they were
   served. These raise the cost of serving a modified client; they do not
   remove the server from the trust base, and the banner stays regardless.

5. **What a web device may not do.** Nothing today. A W0 device is not
   prevented from creating groups or adding members; the 1-hour KeyPackage
   lifetime and the enrollment-per-visit are the only W0-specific behaviours.
   Any future restriction (e.g. web devices may not be the sole device of an
   account) is its own decision.

## Alternatives considered

1. **No web client.** Signal's answer. Rejected by charge: a browser client
   is wanted, with the caveat stated rather than hidden.
2. **Browser extension or "isolated web app" packaging** so the code is
   installed once rather than served per visit. Genuinely closes most of the
   delivery gap. Deferred: it is a distribution channel, not a storage or
   protocol change, and can be layered on `apps/web` later without revisiting
   this ADR. Named here so it is not forgotten.
3. **W1 first, skipping W0.** Rejected: W0 is a two-week proof that the wasm
   core, transports, and KT verification work in a browser at all, and it
   gives the harness a browser client for the Playwright DM test. W1's blob
   discipline is better designed against a working W0 than in the abstract.
4. **Port SQLCipher to wasm.** Rejected: OpenSSL-in-wasm plus a virtual
   filesystem, none of it audited for this use, to end up with a key that is
   still just as reachable by same-origin JavaScript.

## Consequences

- Positive: an honest web client that shares every line of protocol code with
  the native apps; the tier statement is normative text, not marketing.
- Negative: W0 device churn is visible to peers and to the KT log (each visit
  is a new leaf) until W1 lands; W1's "encrypted at rest" is weaker than the
  native store's and is documented as such; two storage backends behind
  `MlsStateStore` to keep in step.
- Follow-ups: `citadel-web` W0 (`web-storage` feature, tier "memory"); the
  Playwright `browser_dm_roundtrip_against_live_stack` job; W1 design details
  (blob format versioning, key rotation on logout, quota handling) as an
  amendment before W1 is built; "device kind" in the credential; the
  self-remove-on-`pagehide` behaviour needs M3's removal path to be honest.

## Evidence

- `web_core_compiles_for_wasm32` (CI `wasm` job).
- `web_tier0_store_reports_memory_only_and_publishes_short_lived_key_packages`
  (the tier name is queryable by the UI, and every published KeyPackage's
  lifetime is ≤ 1 hour).
- `web_transport_maps_gateway_frames_identically_to_native` (shared frame
  fixtures decoded by both transports).
- `shell_reports_encrypted_only_when_backed_by_wasm_core` and
  `banner_is_present_in_every_web_render` (vitest).
- `browser_dm_roundtrip_against_live_stack` (Playwright, headless Chromium,
  in the compose-backed CI job; fails, never skips, when the stack is absent).
- W1: `web_tier1_blob_roundtrips_under_webcrypto_key`,
  `web_tier1_blob_is_rewritten_atomically_per_operation`, and a forward-secrecy
  test in the shape of ADR-0007 §6 before that claim is made.
