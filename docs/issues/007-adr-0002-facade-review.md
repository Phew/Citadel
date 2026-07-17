# 007: Design review — ADR-0002 (service crypto facade). Verdict: approve facade; replace §4 enforcement mechanism

- **Reporter:** k3 (independent design reviewer, AGENTS.md review matrix)
- **Date:** 2026-07-17 (second session; renumbered 005 → 007 on 2026-07-19 —
  Opus holds issues 005/006 on main)
- **Blocks:** charge's acceptance of ADR-0002; Opus's docs/issues/002 (the
  deny-bans request in my lane)
- **Related:** docs/decisions/0002-service-crypto-facade.md (PROPOSED,
  commit d700149 on origin/opus/m1-proto), crates/citadel-service-crypto @
  25a79c4, crates/kt-log @ e8e29d1, docs/issues/002, plans/AGENTS.md rule 6,
  plans/PLAN.md INV-1/INV-2/INV-9/INV-10
- **Evidence branch:** `origin/k3/spike-deny-bans` (f9f58a6) — runnable
  replacement check + the cargo-deny experiment transcript below

## Scope of review

ADR-0002, the facade crate it describes, the kt-log carve-out it references
(ADR-0001 §3), docs/issues/002's concrete proposal, and the actual
dependency graphs of origin/opus/m1-proto and the future merged state
(origin/k3/m1-keypackage-pool, which adds sqlx). Because ADR-0002 §4's
claimed property is "cargo-deny bans can enforce this," I verified that
claim empirically with cargo-deny 0.20.2 rather than taking it on faith.

## What checks out (verified, not skimmed)

- **Crate matches ADR §1 exactly.** `crates/citadel-service-crypto/src/lib.rs`
  exports `verify` (ed25519-dalek `verify_strict` — rejects small/mixed-order
  components, as claimed), `sha256` (sha2), `random_bytes`/`random_array`
  (getrandom 0.2, error is fatal-typed, no fallback path — INV-9 holds).
  Nothing else is exported: no signing, no keygen, no encryption, no KDF,
  no MAC (INV-1/INV-2). Manifest confirms the only primitive deps are
  ed25519-dalek/sha2/getrandom (+ test-only rand in dev-dependencies, used
  solely to generate keypairs for verify() tests — acceptable, and it must
  stay out of `[dependencies]`).
- **Every Evidence claim maps to a real test:** valid signature accepted
  (`verify_accepts_valid_signature`); wrong message / wrong key / flipped
  bit (`verify_rejects_wrong_message_wrong_key_and_flipped_bit`); invalid
  key encoding (`verify_rejects_invalid_public_key_bytes` — note it accepts
  either error variant; fine, but the ADR's "invalid-encoding" wording is
  looser than the test); NIST SHA-256("abc") (`sha256_matches_known_vector`);
  fill-and-vary (`random_bytes_fills_and_varies`).
- **§3 message-bytes discipline is implementable as written:** the
  deterministic builders exist in citadel-proto
  (`auth.rs:107 challenge_signing_input`, `credential.rs:60
  DeviceCredential::signing_input`, `credential.rs:100
  endorsement_signing_input`, `kt.rs:88 TreeHeadTbs::signing_input`), all
  domain-separated under `citadel/v1/...` and golden-byte pinned.
- **§2's kt-log carve-out matches the kt-log manifest:** kt-log depends on
  ed25519-dalek directly (TreeHeadSigner only — lib.rs docs say so and the
  code signs nothing but `TreeHeadTbs::signing_input()`) and takes SHA-256
  from the facade (no sha2 in its manifest). The carve-out is real, narrow,
  and does not flow through the facade, exactly as §2 states.
- **Alternatives §2 (no OpenMLS re-export) is correct** — re-exporting
  group crypto into services would link decryption paths server-side
  (INV-1). Right call, right reason.

## F1 (blocking): §4's enforcement mechanism fails on the current, unmodified tree

ADR-0002 §4 and docs/issues/002 propose `[[bans.deny]]` entries with
`wrappers = ["citadel-service-crypto", "kt-log"]`. I ran exactly that
config against origin/opus/m1-proto (faabd5f) with cargo-deny 0.20.2.
**Result: `bans FAILED` — 7 banned-crate errors on a tree with zero service
crypto violations.** cargo-deny's semantics ([docs](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html)):
a wrapper "allows specific crates to have a direct dependency on the banned
crate but **denies all transitive dependencies on it**" — i.e. EVERY direct
parent of a banned crate anywhere in the resolved graph must be a wrapper.
It does not mean "only workspace members outside the wrapper list are
checked." Observed errors:

```
getrandom 0.2.17  <- parents ring, rand_core 0.6.4        (external)
getrandom 0.3.4   <- parent  rand_core 0.9.5              (external)
getrandom 0.4.3   <- parents uuid 1.24.0, tempfile 3.27.0 (external)
rand 0.9.5        <- parent  proptest 1.11.0 (via dev: kt-log)
rand_core 0.6.4   <- parents rand_chacha, rand 0.8, ed25519-dalek
rand_core 0.9.5   <- parents rand 0.9.5, rand_chacha, rand_xorshift
ring 0.17.14      <- parents rustls 0.23.42, rustls-webpki (via reqwest)
sha2 0.10.9       <- parent  ed25519-dalek 2.2.0          (external!)
```

Only ed25519-dalek itself passed (both its parents are the wrappers). Note
sha2 fails *because of the facade's own ed25519-dalek*: the ban punishes the
wrapper's transitive subtree.

It gets worse after my stack merges: sqlx (k3/m1-keypackage-pool) puts
sqlx-mysql directly on hkdf, hmac, md-5, rand, rsa, sha1, sha2 and
sqlx-postgres on hkdf, hmac, md-5, rand, sha2 — seven of the twelve banned
crates gain external parents. Making the proposed config pass would require
naming uuid, tempfile, proptest, rustls, rustls-webpki, ring, rand_core,
ed25519-dalek, sqlx-mysql, sqlx-postgres, ... in `wrappers` — whack-a-mole
that also corrupts the audit meaning ("sqlx may use crypto" is nonsense).
`skip`/`skip-tree` are not a fix: they allow the crate *anywhere*, including
as a service's direct dependency — they dissolve the ban.

**Proposed replacement (built and tested, `k3/spike-deny-bans` f9f58a6):**
`ci/check_crypto_confinement.py` — a ~100-line stdlib-only script that runs
`cargo metadata --no-deps` and fails if any of the four service crates
declares a direct dependency (normal, dev, build, or target-specific;
rename-safe — metadata reports the real package name) on a 33-crate
blocklist. Test matrix on origin/opus/m1-proto, all reproduced on the spike
branch:

| Scenario | Result |
|---|---|
| clean tree | PASS |
| auth-service + sha2 `[dependencies]` | FAIL, names crate + dep |
| directory-service + rand `[dev-dependencies]` | FAIL, names kind |
| auth-service + `alias = { package = "sha2" }` rename | FAIL (rename-safe) |
| citadel-core + sha2 | PASS — out of scope, see F3 |
| injected probe (self-test) | detected, or the check exits 1 |
| a service crate missing from metadata | exits 1, never vacuous-pass |

This is what issue 002's own escape hatch asks for ("or an equivalent CI
check"), and it is NOT blocked on opus/m1-proto merging — it inspects
manifests, not the facade. Request: Opus amend ADR-0002 §4 to name this
check as the mechanism (deny.toml retains advisories/licenses/multiple-versions,
optionally plus whole-graph bans only for crates nothing may ever use —
e.g. openssl-sys, native-tls — both absent today); charge accepts with that
amendment; I then wire the script into the audit CI job as the real PR with
this same matrix as its evidence.

## F2 (major): the §4 deny list is both under-specified and under-inclusive

"ed25519-dalek, sha2, ring, rustls' crypto internals, rand for key-material
paths, etc." is not auditable — "etc." and "rustls' crypto internals" have
no checkable referent. Even issue 002's concrete 12-crate list misses the
likely evasion/accident vectors: aws-lc-rs (rustls's default backend, one
feature-flip away), the openmls* crates (a service linking OpenMLS is the
sharpest INV-1 violation there is, and a dependency check is the only
build-time guard against it), x25519-dalek/curve25519-dalek (ECDH evasion),
k256/p256/rsa (rsa is *already in our merged graph* via sqlx-mysql —
transitive use is fine, direct must fail), blake2/blake3/sha3 (hash
evasion), aes/chacha20 (raw ciphers), pbkdf2/argon2/scrypt (KDFs), merlin.
The spike script's blocklist covers all of the above, grouped by family
with per-entry reasons. Request: ADR-0002 §4 stops embedding a list and
points at the check's blocklist as canonical; extensions go through
docs/issues/ escalation per rule 6, never quietly.

## F3 (major, forward-looking): confinement scope must be stated as service crates only — the M2 break otherwise

Rule 6 confines *services*. The cargo-deny mechanism confines *every
first-party crate outside the wrapper list* — silently including
citadel-core, which in M2 MUST take direct crypto deps (the OpenMLS
provider stack, and per F1 step 1 an Ed25519 identity-key crate). Under the
proposed mechanism, Opus's first M2 citadel-core commit breaks CI with no
clean remedy (adding citadel-core to `wrappers` blesses client crypto —
which is semantically correct, but the ADR never says so). The scoped check
avoids this by construction (T4 above: citadel-core + sha2 passes).
Request: ADR-0002 §4 states explicitly that citadel-core, apps/desktop, and
test-harness are outside this check's scope — client crypto is governed by
INV-9/INV-10 and Opus's blocking review; a separate allowlist check for
client crates can be ADR'd in M2 if charge wants belt-and-braces.

## F4 (minor): "rand for key-material paths" is not a mechanically expressible rule

§4's carve-out implies partial scoping that no checker can verify. The
rule that CAN be verified — and the one the facade's docs already endorse —
is: **no rand/rand_core/getrandom in service manifests for any purpose;
all service randomness (challenges, tokens, invite codes, jitter) comes
from `random_bytes`/`random_array`.** Stricter than the ADR's wording and
I believe the intended reading; flagging so Opus confirms or corrects.

## F5 (nits, non-blocking)

- Facade pins getrandom 0.2 (`getrandom::getrandom`); the graph already
  carries 0.3/0.4 via rand_core/uuid/tempfile (API renamed to `fill` in
  0.3). Not a defect; when the facade eventually bumps, do it deliberately
  to keep the audit surface at one version.
- Consider a public-API surface guard (e.g. a doc test or a tiny
  `#[test]` asserting the crate root exports nothing beyond the three
  capabilities) so capability creep between reviews is caught by CI rather
  than by re-reading. Optional; the blocking-review process may suffice.
- dev-dependencies of service crates are in scope of the spike check on
  purpose: a service test must not sign or hash ad hoc either. The
  cargo-deny experiment showed dev edges are included in its bans by
  default (the proptest→rand error arrived via `(dev) kt-log`), so the two
  mechanisms agree on that point.

## Bottom line for charge

The facade itself — the thing ADR-0002 actually decides — is right, minimal,
and fully evidenced. Approve it. The §4 enforcement paragraph as written is
unimplementable on our graph; the replacement is built, tested, and waiting
on `k3/spike-deny-bans`, and issue 002 already authorizes an equivalent
check. Suggested path: Opus amends §4 per F1/F2/F3/F4 (one paragraph plus a
pointer at the script), you accept ADR-0002, I ship the CI wiring + deny.toml
cleanup as a normal k3 PR — no longer blocked on opus/m1-proto.
