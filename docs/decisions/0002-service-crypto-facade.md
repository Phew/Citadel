# ADR-0002: citadel-service-crypto — the three-capability service crypto facade

- **Status:** ACCEPTED (design, charge 2026-07-17) — **§4 enforcement: PROPOSED amendment (2026-07-18), awaiting charge re-acceptance.** The facade design charge accepted is unchanged; only §4's enforcement *mechanism* is amended (see Revision history).
- **Date:** 2026-07-17 (rev 1); 2026-07-18 (rev 2, §4 amendment)
- **Deciders:** charge (required for ACCEPTED); author: Opus. Design review: K3.
- **Invariants touched:** INV-1, INV-2, INV-9, INV-10
- **Related:** plans/AGENTS.md rule 6; crates/citadel-service-crypto; ADR-0001 (signing carve-out); docs/issues/002 (superseded by rev 2); K3's ADR-0002 design review (`origin/k3/m1-adr0002-review`, renumbered 007 in K3's lane); evidence spike `origin/k3/spike-deny-bans` (f9f58a6)

## Revision history

- **rev 1** (accepted by charge 2026-07-17): facade design + §4 enforcement via
  cargo-deny `[[bans.deny]]` with `wrappers = [...]`.
- **rev 2** (this change, PROPOSED): K3 design-reviewed the facade and verified
  empirically that §4's cargo-deny mechanism is unimplementable on our graph —
  `[[bans.deny]]` `wrappers` are graph-wide, so *every* direct parent of a
  banned crate (uuid, tempfile, proptest, rustls/ring, the sqlx backends, and
  even the facade's own ed25519-dalek → sha2 edge) must be named a wrapper, and
  the config `bans FAILED` with 7 errors on a clean tree. **The facade design
  charge accepted (§1–§3) is untouched; only §4 changes.** §4 now names K3's
  scoped `ci/check_crypto_confinement.py` (a `cargo metadata --no-deps` check
  over the four service crates' direct dependencies) as the enforcement
  mechanism. docs/issues/002 (the original cargo-deny-bans request) closes as
  **superseded** when this amendment lands.

  **Opus concurrence (independent reproduction, 2026-07-18):** ran K3's
  proposed `[[bans.deny]]`/`wrappers` config against the current tree with
  cargo-deny 0.20.2 → `bans FAILED`, with `unmatched-wrapper` warnings naming
  ring, rand_core, uuid, tempfile, proptest, and `ed25519-dalek` (the facade's
  own subtree) as banned-crate parents — exactly K3's finding, including the
  decisive `sha2 <- ed25519-dalek` edge that no wrapper list can express
  without lying about the audit meaning. Ran `ci/check_crypto_confinement.py`
  from the spike branch against the same tree → PASS (clean), with its
  self-test firing. I concur with F1–F4; §4 below adopts them.

## Context

AGENTS.md rule 6 mandates that server-side services touch cryptography only
through an Opus-owned facade exposing verify, sha256, and OS-CSPRNG bytes.
This ADR records the concrete crate design and the enforcement plan so the
rule is checkable rather than aspirational.

## Decision

1. **Crate:** `citadel-service-crypto` exposes exactly:
   - `verify(pk32, msg, sig64)` — Ed25519 via ed25519-dalek `verify_strict`
     (rejects small/mixed-order components; cheap malleability insurance);
   - `sha256(data)` — via the `sha2` crate;
   - `random_bytes(buf)` / `random_array::<N>()` — via `getrandom` (OS
     CSPRNG, INV-9). RNG failure is a fatal error; no fallback source.
2. **Deliberately absent:** signing, key generation, encryption, decryption,
   KDFs, MACs. Services hold no user keys (INV-2) and no plaintext (INV-1).
   The single sanctioned exception is tree-head signing, encapsulated inside
   kt-log (ADR-0001 §3), which does not flow through or extend this facade.
3. **Message bytes discipline:** callers pass the deterministic signing
   inputs defined in citadel-proto (`signing_input()` builders); services
   never construct signing inputs ad hoc.
4. **Enforcement — scoped direct-dependency check (rev 2; supersedes the
   rev-1 cargo-deny-bans paragraph and docs/issues/002).**

   The rule to enforce is: *the four service crates — auth-service,
   delivery-service, directory-service, blobstore-service — declare no direct
   dependency on any crypto-primitive crate.* Services reach crypto only
   through this facade (verify/sha256/random); kt-log's encapsulated tree-head
   signing is the single sanctioned exception (ADR-0001 §3).

   - **Mechanism: `ci/check_crypto_confinement.py`** (K3's lane; Opus review).
     A stdlib-only script that runs `cargo metadata --no-deps` and fails if any
     service crate declares a direct dependency — normal, dev, build, or
     target-specific — on a crate in its blocklist. It reads the *real* package
     name from metadata, so a manifest rename (`alias = { package = "sha2" }`)
     does not evade it. It fails loudly (exit 1) rather than passing vacuously
     if a service crate is missing from the workspace, and carries a self-test
     that an injected violation is detected.

   - **Why not cargo-deny `[[bans.deny]]` (rev 1's mechanism).** cargo-deny
     `wrappers` are *graph-wide*: a wrapper permits the named crate a direct
     edge to the banned crate but denies **all** transitive dependencies on it,
     i.e. every direct parent of a banned crate anywhere in the resolved graph
     must be a wrapper. On our clean tree that config `bans FAILED` — sha2 via
     the facade's own ed25519-dalek, getrandom via ring/rand_core/uuid/tempfile,
     rand via proptest, ring via rustls — and after sqlx merges, seven banned
     crates gain external parents (sqlx-mysql/-postgres → hkdf, hmac, sha2, …).
     Making it pass would require listing uuid, tempfile, proptest, rustls,
     ring, ed25519-dalek, the sqlx backends, … as `wrappers`, which is
     whack-a-mole that also corrupts the audit meaning ("sqlx may use crypto").
     `skip`/`skip-tree` are worse: they allow the crate anywhere, dissolving the
     ban. Verified with cargo-deny 0.20.2 by both K3 (`origin/k3/spike-deny-bans`
     f9f58a6) and Opus (Revision history). A manifest-scoped check enforces
     exactly what rule 6 governs — what a *service* declares — and nothing else.

   - **The blocklist is canonical in the script, not embedded here** (was rev
     1's inline "ed25519-dalek, sha2, ring, …, etc." — "etc." and "rustls'
     crypto internals" have no checkable referent). The script's blocklist
     covers, grouped by evasion family with per-entry reasons: signatures
     (ed25519-dalek, ed25519, k256, p256, rsa, schnorrkel), ECDH/EC
     (x25519-dalek, curve25519-dalek), hashes (sha2, sha1, sha3, md-5, blake2,
     blake3), AEAD/ciphers (aes-gcm, chacha20poly1305, aes, chacha20), MAC/KDF
     (hmac, hkdf, pbkdf2, argon2, scrypt), RNG (rand, rand_core, getrandom), TLS
     crypto backends (ring, aws-lc-rs), transcripts (merlin), and — the sharpest
     INV-1 guard — group crypto (openmls and its provider crates: a service that
     links OpenMLS links decryption paths server-side). Additions go through
     docs/issues/ escalation per rule 6, never quietly.

   - **Scope is service crates only.** citadel-core, apps/desktop, and
     test-harness are **out of scope** of this check: client crypto is
     legitimate (INV-2 — the client holds user keys; F1 step 1 needs an Ed25519
     identity crate; M2 needs the OpenMLS provider) and is governed by
     INV-9/INV-10 and Opus's blocking review, not by this dependency gate. This
     is deliberate: the graph-wide cargo-deny mechanism would have broken CI on
     Opus's first M2 citadel-core crypto commit with no clean remedy. A separate
     client-crate allowlist check may be ADR'd in M2 if charge wants
     belt-and-braces.

   - **Randomness rule (mechanically precise).** No `rand`/`rand_core`/
     `getrandom` in any service manifest for *any* purpose — challenges, tokens,
     invite codes, jitter all come from the facade's `random_bytes`/
     `random_array` (INV-9's single choke point). This is stricter than rev 1's
     unverifiable "rand for key-material paths" and is what the check enforces.

   - **deny.toml is retained for what it is actually good at:** advisories
     (RUSTSEC), license policy, and multiple-versions hygiene — plus, optionally,
     *whole-graph* `bans` for crates nothing in the workspace may ever link
     (e.g. openssl-sys, native-tls; both absent today), where graph-wide
     semantics are the desired behaviour, not a bug. It is **not** the canonical
     list for the service-confinement rule.

   Until the check is wired into CI, review is the enforcement (unchanged from
   rev 1). K3 ships the CI wiring + deny.toml cleanup as a normal PR with the
   spike's test matrix as evidence; it is not blocked on any facade change.

## Alternatives considered

1. **Each service depends on primitive crates directly** — smallest code,
   but the "no fourth capability" property becomes unauditable; exactly what
   rule 6 exists to prevent.
2. **Re-export OpenMLS provider primitives** — drags group-crypto machinery
   into services that must never link decryption paths (INV-1); wrong
   dependency direction.
3. **`ring` instead of dalek/sha2** — fine primitives, but ed25519-dalek is
   already the transitive base of the OpenMLS rust-crypto provider, keeping
   one Ed25519 implementation across the workspace.

## Consequences

- Positive: one small file is the entire service crypto surface; auditors
  read ~80 lines; INV-9 has a single choke point.
- Negative: a genuinely new service need (e.g. HMAC for franking
  countersignature in M6) forces an escalation and ADR. That is intended
  friction — M6 will get its own ADR rather than a quiet facade extension.
- Follow-ups: `ci/check_crypto_confinement.py` CI wiring + deny.toml cleanup
  (K3, M1 CI hardening — rev 2 §4); M6 franking countersignature capability
  review; optional M2 client-crate allowlist check (rev 2 §4 scope note).

## Evidence

- Unit tests: valid/tampered/wrong-key/invalid-encoding verify cases, NIST
  SHA-256("abc") vector, CSPRNG fill-and-vary.
- **Enforcement (rev 2):** `ci/check_crypto_confinement.py` (K3,
  `origin/k3/spike-deny-bans` f9f58a6) with its test matrix — clean tree PASS;
  service + sha2/rand in normal/dev deps FAIL and names the crate + kind;
  `alias = { package = "sha2" }` rename FAIL (rename-safe); citadel-core + sha2
  PASS (out of scope); missing service crate → exit 1 (never vacuous-pass);
  injected-probe self-test fires. Reproduced by Opus on the current tree
  (Revision history), alongside the cargo-deny `bans FAILED` result that
  motivated replacing rev 1's mechanism.
