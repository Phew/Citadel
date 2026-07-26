# 009: K3 review — CHANGES. ADR-0007 (local encrypted client store) design review

- **Reporter:** k3 (independent design reviewer, AGENTS.md review matrix)
- **Date:** 2026-07-26
- **Blocks:** charge's acceptance of ADR-0007; the store build; M2 exit
  criterion `device_compromise_past_messages_unreadable_fs`; all of M2's
  remaining queue
- **Related:** docs/decisions/0007-local-encrypted-client-store.md (PROPOSED,
  `7592a26`), plans/PLAN.md §§4, 9 M2, 13; deny.toml; .cargo/audit.toml;
  docs/status/advisor.md queue item 1

**Verdict: CHANGES.** Two narrow amendments are required before ACCEPTED
(F1, F2). Everything else in the ADR is approved as written, and this
verdict should not read as a rejection: the store design — key handling,
fail-closed state machine, transaction contract, deletion semantics, and
the forward-secrecy/PCS evidence package — is strong and should survive
unchanged. Sol authored the ADR and is out of quota this week; the review
was conducted on the merits against source, and a Sol re-review of these
findings is welcome when quota resets.

## How the load-bearing question was answered

The assigned question: does a **named advisory affecting the stock bundled
SQLCipher 4.5.7's embedded SQLite in this usage** exist? I answered it from
primary sources and from the advisory tooling my lane owns, not from
assertion:

- **The embedded version.** libsqlite3-sys 0.30.1's bundled SQLCipher
  amalgamation reports `SQLITE_VERSION = "3.45.3"` (verified in the crate's
  `sqlcipher/bindgen_bundled_version.rs` and `sqlite3.h`; matches the
  SQLCipher changelog: 4.5.7, April 2024, "Updates baseline to upstream
  SQLite 3.45.3"). The ADR's factual premise is accurate.
- **Named CVEs against 3.45.3 do exist** (sqlite.org/cves.html, fetched
  2026-07-26): CVE-2025-3277 (= CVE-2025-29087, `concat_ws()` heap write,
  fixed 3.49.1), CVE-2025-6965 (integer overflow, fixed 3.50.2),
  CVE-2025-7709 (FTS5 corrupt index, fixed 3.50.3), CVE-2025-29088
  (`sqlite3_db_config` LOOKASIDE misuse, fixed 3.49.1), and
  CVE-2026-11822/11824 (FTS5 heap write, fixed 3.53.2). So the honest
  answer to the literal question is yes, named advisories exist.
- **None is applicable in this usage.** Every one requires a precondition
  the ADR's own design forecloses: attacker-controlled SQL (all of them —
  the store's SQL is entirely application-constructed and attacker data
  arrives as bound parameters); an attacker-crafted database file
  (CVE-2025-7709's precondition — defeated by SQLCipher page HMAC under the
  database encryption key); FTS5 (CVE-2025-7709, CVE-2026-11822 — the build
  omits FTS5 and the app never creates FTS5 tables); `DBCONFIG_DEFENSIVE`
  off (CVE-2026-11822 — §3 pins it ON); or the application misusing a C API
  itself (CVE-2025-29088 — rusqlite never exposes LOOKASIDE configuration
  to attacker influence). sqlite.org's own executive summary states that
  CVEs about SQLite "probably do not apply to your use of SQLite" absent
  arbitrary-SQL or crafted-file preconditions; both are designed out here.
- **cargo-audit agrees.** I resolved the ADR's exact pinned graph in a
  scratch crate (`rusqlite =0.32.1` + `bundled-sqlcipher-vendored-openssl`,
  `libsqlite3-sys =0.30.1`, `openmls_sqlite_storage =0.2.0`,
  `refinery =0.9.2`, `keyring =3.6.3`, `windows-sys =0.61.2`,
  `serde_json =1.0.150`, plus dev-deps `mls-rs =0.55.2`, `mls-spec =2.0.1`,
  `mls-rs-crypto-awslc =0.25.0`) and ran the repo's own audit config:
  **zero advisories on any crate the ADR introduces**, Rust or bundled-C.
  (The only hits were the pre-existing OpenMLS/hpke-rs/libcrux chain, an
  artifact of the probe resolving hpke-rs 0.5.1 where main's lockfile pins
  the fixed 0.6.1; main is green.) RustSec does issue advisories for
  bundled C when warranted — RUSTSEC-2022-0090 covered exactly a
  libsqlite3-sys bundled-SQLite CVE — so the silence is meaningful, though
  not proof; the CVE-table analysis above is the proof.

## Findings (must resolve before ACCEPTED)

### F1 — Alternative 2's rejection of the stock bundle fails the ADR's own gating test; stage the overlay

ADR §1 and Alternative 2 reject the stock 4.5.7 bundle because it "is not
4.17.0, which incorporates current upstream SQLite fixes." That is a
freshness preference, not a named threat, and §1's own rule — "a relevant
advisory blocks this choice" — is not triggered by any advisory applicable
in this usage (evidence above). Yet everything expensive in the ADR hangs
off that one line: the repository-local libsqlite3-sys patch, vendored
OpenSSL with pinned Configure transcripts, pinned NASM, three-OS
amalgamation byte-comparison, CycloneDX SBOM, and OSV scanning — plausibly
more work than the rest of M2 combined, and an indefinite commitment to
maintaining a fork of a C crypto library's build glue.

**Proposed fix: stage it.**

- M2 ships the store on the stock
  `bundled-sqlcipher-vendored-openssl` bundle (SQLCipher 4.5.7). The
  overlay and its full reproducibility program become their own ADR,
  justified on their own merits if and when charge wants them.
- Keep a **lightweight** version of the native manifest plus OSV/security-
  notice scan of the *stock* bundle in the store build. That is the
  tripwire that detects a future advisory that actually is relevant to this
  usage — under staging it becomes more important, not less — and it costs
  a CI job, not a fork.
- Two concrete adjustments staging forces, both small:
  1. §3's open sequence verifies "an active encryption codec through
     `PRAGMA cipher_status`" — but `cipher_status` was **added in SQLCipher
     4.12.0** (changelog, December 2025) and does not exist on 4.5.7. The
     staged build must substitute the already-mandatory encrypted-schema-
     access probe (a wrong key fails schema access regardless) plus
     `cipher_integrity_check` at creation (available since 4.2.0).
  2. §1's pinned `SQLITE_EXTRA_INIT/SHUTDOWN=sqlcipher_extra_*` flags are
     **mandatory only from SQLCipher 4.7.0** (its breaking-change notes);
     the staged flag set must be re-derived for 4.5.7, and
     `store_release_uses_only_pinned_sqlcipher` must read back `PRAGMA
     cipher_version` = 4.5.7. The evidence test names are unchanged; only
     the pinned values move.
- Fairness, stated plainly: SQLCipher 4.7.0+ does buy real defense-in-depth
  (keyspec obfuscation, fast overwrite of freed memory, `cipher_status`
  itself). If charge wants those properties, the proportionate path is a
  dedicated ADR that names *them* as the reason — not a freshness line that
  smuggles in a fork-maintenance program.

### F2 — The ADR never names its collision with deny.toml's whole-graph `openssl-sys` ban

`bundled-sqlcipher-vendored-openssl` resolves as
`["bundled-sqlcipher", "openssl-sys/vendored"]`: the graph gains
`libsqlite3-sys 0.30.1 → openssl-sys 0.9.117` (verified with `cargo tree`).
deny.toml bans `openssl-sys` **graph-wide** ("TLS is rustls-only; the
native-TLS/openssl stack must never enter the graph"), and both configs are
load-bearing with audit running first. Reproduced against the repo's own
deny.toml (cargo-deny 0.20.2):

```
error[banned]: crate 'openssl-sys = 0.9.117' is explicitly banned
```

audit passes the new surface; **deny is where the ADR collides**, and it
collides on either path — plain `bundled-sqlcipher` without
`vendored-openssl` drops openssl-sys (verified) but then needs a system
OpenSSL to link, which does not exist on the Windows target of the ADR's
own three-OS matrix. Vendored OpenSSL is effectively required regardless of
F1's outcome.

**Proposed fix (proven, one line):** narrow the ban with a wrapper
restriction —

```toml
{ name = "openssl-sys", wrappers = ["libsqlite3-sys"], reason = "SQLCipher page codec links vendored OpenSSL via libsqlite3-sys; not a TLS stack" }
```

I applied exactly that edit to a copy of the repo's deny.toml and re-ran
`cargo deny check bans` over the ADR's full dependency surface: **bans
ok**. The ban's stated purpose is untouched — no TLS stack enters; the
OpenSSL build serves SQLCipher's page codec only. What the ADR must do is
*name* this amendment (one sentence in §1 or Consequences), because
silently requiring a load-bearing config change is how configs drift.
`.cargo/audit.toml` needs no change. The license allowlist already covers
the entire new Rust surface including the aws-lc-rs chain (probe: licenses
pass).

## What was verified strong (approved as written; must survive)

- **The forward-secrecy test's demanded error chain is real.** Reproduced
  against openmls 0.8.1 source: the application-message (PrivateMessage)
  path maps a missing epoch secret tree to
  `MessageDecryptionError::SecretTreeError` (framing/validation.rs:107),
  `SecretTreeError::TooDistantInThePast` is produced by the secret-tree
  lookup (group/mls_group/mod.rs:533+), and
  `ValidationError::UnableToDecrypt` is `#[from] MessageDecryptionError`
  (group/errors.rs:422), wrapped by `ProcessMessageError::ValidationError`.
  OpenMLS's own `past_secrets.rs:152` asserts the identical chain. The ADR
  is also right in a subtle way worth recording: for *PublicMessage* the
  same condition surfaces as `ValidationError::NoPastEpochData`
  (processing.rs:677) — so the test correctly demands an old-epoch
  **application** ciphertext, and a handshake-message probe would not
  exercise the demanded chain. Handing the attacker the database, every
  sidecar, AND the correct database encryption key, then refusing parser
  errors / app-level epoch comparison / replay rejection as evidence, is
  exactly the right adversary model.
- **The PCS design blocks M2 close rather than substituting a
  self-referential test** — the correct call, and the oracle pins
  (`mls-rs 0.55.2`, `mls-spec 2.0.1`, `mls-rs-crypto-awslc 0.25.0`) all
  resolve on crates.io as CI-validation (dev) dependencies with zero
  advisories. Note for CI planning: the aws-lc-sys C build adds toolchain
  cost to the interop job only; the release-graph exclusion is covered by
  `store_release_excludes_secret_evidence_paths`.
- **The shared-transaction type argument reproduces** at the level the ADR
  asks of this review: rusqlite 0.32.1 has
  `impl Deref for Transaction<'_> { type Target = Connection }`
  (transaction.rs:232) and the provider is
  `SqliteStorageProvider<C: Codec, ConnectionRef: Borrow<Connection>>`
  (openmls_sqlite_storage 0.2.0, storage_provider.rs:31), so
  `&*transaction` satisfies the bound. The ADR is correct that this is not
  build evidence; acceptance properly waits on
  `store_provider_and_application_share_one_transaction`.
- **The keyring justification is factually accurate:** keyring 3.6.3
  hard-codes `CRED_PERSIST_ENTERPRISE` (src/windows.rs:246), so the direct
  `windows-sys 0.61.2` adapter with `CRED_PERSIST_LOCAL_MACHINE` is
  warranted, not gold-plating.
- **Dependency-graph claims check out:** exactly one `rusqlite` and one
  `libsqlite3-sys` resolve; `openssl-src` resolves to exactly
  `300.6.1+3.6.3` (the ADR's pin); every pinned version exists on
  crates.io; rust-toolchain pins 1.95.0 so `File::try_lock` is stable;
  current citadel-core is `OpenMlsRustCrypto` (in-memory; crypto.rs:16),
  so the ADR's context and the FS-test deferral rationale stand.

## Non-blocking notes

- §6 says `max_past_epochs` is pinned to zero "instead of inheriting the
  OpenMLS default." In openmls 0.8.1 **the default is already 0**
  (group/mls_group/config.rs:50-52, struct derives `Default`). The explicit
  pin is still correct — its value is fail-closed drift protection against
  an upstream default change, which the ADR's next sentence states — but
  the phrasing implies the current default is non-zero. One-line
  correction; no re-review needed.
- The `store_epoch_transition_removes_obsolete_secret_bytes` evidence test
  uses `SQLITE_ENABLE_DBPAGE_VTAB` + upstream `dbdata.c` recovery against
  the *pinned* SQLCipher source. Under F1 staging that evidence build pins
  4.5.7; the technique is version-portable, but the test's build recipe
  must follow whichever bundle ships.

## Structural flag for charge (noted, not decided)

ADR-0007 §6 narrows PLAN §9 M2's "past messages unreadable" to a
persisted-state boundary: current MLS secret state cannot decrypt
old-epoch ciphertext, while deliberately retained decrypted history stays
readable to anyone holding the database encryption key. Technically this is
sound — MLS forward secrecy is a property of key material, not of a local
plaintext archive, Signal behaves the same way, and unreadable retained
history is a retention feature the ADR correctly defers — and the advisor
endorses it. But AGENTS.md reserves acceptance-criterion changes to charge
specifically, so it must be a conscious, separately-stated decision, not
something inherited by accepting this ADR. The two decisions (accept the
ADR; narrow the AC) should land as two decisions.

## Recommendation

Amend per F1 (stage the overlay; ship M2 on the stock bundle with the
lightweight native-manifest + OSV tripwire; adjust the `cipher_status` and
EXTRA_INIT details) and F2 (name the deny.toml `wrappers` narrowing in the
ADR text). With those two amendments the ADR is approved from the K3
review seat. The store design, the transaction and deletion contracts, and
the FS/PCS evidence package are the right calls and should not be reopened.
