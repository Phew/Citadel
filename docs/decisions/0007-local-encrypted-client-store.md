# ADR-0007: Local encrypted client store

- **Status:** **ACCEPTED** (charge, 2026-07-26), body as amended. Amendment 1
  **ACCEPTED** in the same decision. K3's independent design review returned CHANGES,
  its two blocking findings were folded as Amendment 1, and K3's re-review returned
  **APPROVE** (`docs/issues/009` rev 2, merged `289c570`). Recorded by the advisor on
  charge's instruction. Build may start.
  Two non-blocking notes from the re-review were **not** folded at acceptance and were
  tracked in `docs/issues/011-adr-0007-non-blocking-notes.md`. Both landed with the store
  build and are folded into Amendment 1 §A.5 and §A.7; the issue is CLOSED.
- **Date:** 2026-07-24 (body); 2026-07-26 (Amendment 1)
- **Amendment 2:** **ACCEPTED** (charge, 2026-08-14). It takes effect when
  PR #69 merges; until then, the accepted text on `main` remains controlling.
- **Deciders:** charge (required for ACCEPTED); independent design review: K3
  **complete — CHANGES**, `docs/issues/009-adr-0007-store-design-review.md`
  (merged `9ca9317`). Its two blocking findings are folded as Amendment 1 below.
- **Invariants touched:** INV-1, INV-2, INV-4, INV-5, INV-9, INV-10
- **Related:** plans/PLAN.md §§3, 4, 6, 9 M2, and 13; ADR-0001 §5;
  ADR-0005 §4; OpenMLS 0.8.1; `deny.toml` (Amendment 1 §B);
  docs/issues/009 (the review this amendment answers)
- **Supersedes on acceptance:** ADR-0005 §4, its M2 forward-secrecy and
  post-compromise security evidence definitions, and the `sqlx` part of
  plans/PLAN.md §4's client-store row; it also replaces PLAN §9 M2's broad
  "past messages unreadable" wording with the persisted-state evidence boundary
  in §6

## Context

M2 requires a local encrypted SQLite store and a device-compromise test that
proves old MLS ciphertext remains unreadable after obsolete state is deleted.
The current `citadel-core` uses `OpenMlsRustCrypto`, whose storage provider is
in-memory. A process restart loses all MLS state, and there is no durable state
whose deletion can support an honest forward-secrecy test.

ADR-0005 §4 named a 32-byte database encryption key in the OS credential store
and a "SQLCipher-style" mechanism, but left the mechanism, platform behavior,
failure behavior, transaction boundary, and destruction semantics to the
build. It also said it reused an M1 credential-store integration that was never
built. That is not enough to authorize security-sensitive key handling.

This ADR is a narrow replacement for ADR-0005 §4. It does not change the M2
wire model, padding, KT verification, delivery service, or the M3 commit-ordering
scope.

## Decision

### 1. Storage and encryption libraries

> **Amended by Amendment 1 §A.** The SQLCipher 4.17.0 source overlay, its
> reproducibility program, and its pinned compile-flag set are **staged out of
> M2**. M2 ships the stock bundled SQLCipher 4.5.7. The paragraphs below
> describing the overlay, the vendored-OpenSSL Configure transcripts, the pinned
> NASM artifact, and the immutable builder matrix record the original proposal
> and are **not M2 scope**; read Amendment 1 §A for what M2 actually builds.
> Amendment 1 §B additionally names this section's collision with `deny.toml`.

`citadel-core` will use:

- SQLCipher Community Edition for whole-database encryption;
- `rusqlite` 0.32.1 with `bundled-sqlcipher-vendored-openssl`, resolving
  `libsqlite3-sys` 0.30.1;
- a repository-local patch of `libsqlite3-sys` 0.30.1 that replaces its stock
  SQLCipher 4.5.7 amalgamation with SQLCipher Community 4.17.0, matching
  generated bindings, and the required current build flags;
- OpenMLS's published `openmls_sqlite_storage` 0.2.0 provider, which uses
  `openmls_traits` 0.5.0, `refinery` 0.9.2, and the same `rusqlite` 0.32
  line; and
- the existing `openmls_rust_crypto::RustCrypto` implementation for OpenMLS
  cryptography and randomness.

A Citadel provider will combine `RustCrypto` with
`openmls_sqlite_storage::SqliteStorageProvider`. It replaces the
`OpenMlsRustCrypto` alias, but does not replace any MLS primitive.

The SQLCipher overlay contains the upstream 4.17.0 tag and commit identity,
source digest, license material, amalgamation, header, and regenerated
bindings. A committed reproducibility check downloads the pinned source
archive, verifies its SHA-256, regenerates the artifacts in a build container
pinned by image digest, and byte-compares them with the committed copies.
Release builds use no system SQLite, SQLCipher, `pkg-config`, vcpkg, or
`SQLCIPHER_*` environment input. Clean Windows, macOS, and Linux builds must
prove that `cargo tree` contains one `rusqlite` and one `libsqlite3-sys`, that
exactly one statically linked SQLCipher engine is present, and that
`PRAGMA cipher_version` returns exactly `4.17.0`.

The locked native graph resolves `openssl-src` exactly
`300.6.1+3.6.3`, containing OpenSSL 3.6.3, with its default feature set.
The initial release matrix is `x86_64-pc-windows-msvc`,
`aarch64-apple-darwin`, and `x86_64-unknown-linux-gnu`; supporting another
target requires extending this matrix and its evidence first. The corresponding
OpenSSL Configure targets are `VC-WIN64A`, `darwin64-arm64-cc`, and
`linux-x86_64`. The common option vector is `no-shared`, `no-module`,
`no-tests`, `no-comp`, `no-zlib`, `no-zlib-dynamic`, `--libdir=lib`,
`no-legacy`, `no-ssl3`, `no-md2`, `no-rc5`, `no-weak-ssl-ciphers`,
`no-camellia`, `no-idea`, and `no-seed`; Windows also uses `no-capieng`.
Generated prefix and OpenSSL-directory path arguments are normalized before
comparison. The exact Cargo feature graph and the Configure command transcript
must match the committed native manifest.

Windows x86-64 assembly is required, not environment-detected:
`OPENSSL_RUST_USE_NASM=1` and the upstream
`nasm-3.02-win64.zip` artifact are pinned by version and SHA-256 in the native
manifest. Absence or version drift fails the build rather than selecting
`no-asm`. The immutable builders also pin Perl, the C toolchain, and GNU Make
on macOS and Linux, and the Visual Studio Build Tools image and `nmake.exe` on
Windows. Their executable versions and image or artifact digests are manifest
inputs. The reproducibility job rejects ambient `PERL`, `OPENSSL_SRC_PERL`,
`MAKEFLAGS`, tool-path, NASM, or compiler overrides that differ from those
inputs.

The overlay pins `SQLITE_HAS_CODEC`,
`SQLITE_EXTRA_INIT=sqlcipher_extra_init`,
`SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`,
`SQLCIPHER_CRYPTO_OPENSSL`, `SQLITE_THREADSAFE=1`, and
`SQLITE_TEMP_STORE=3`. It removes the stock FTS5 enablement and compiles with
`SQLITE_OMIT_LOAD_EXTENSION` because the local encrypted client store uses
neither capability. Release evidence reads back the relevant compile options
and cryptographic provider.

The overlay is necessary because the otherwise-compatible published provider
resolves `libsqlite3-sys` 0.30.1, whose stock SQLCipher is 4.5.7. SQLCipher
4.17.0 incorporates current upstream SQLite fixes. A provider fork to current
`rusqlite` is larger than a source overlay because the OpenMLS provider's
`refinery` migration chain is also tied to the older `rusqlite` line. The Rust
wrapper and migration dependencies remain subject to advisory and license
checks; a relevant advisory blocks this choice and requires a provider upgrade.
`cargo audit` and `cargo deny` cover only the Rust graph. A separate committed
native manifest records the SQLCipher tag and digest, embedded SQLite version,
vendored OpenSSL version, source archives, compile flags, and exact license
texts. A reproducible job generates a CycloneDX SBOM, runs OSV-Scanner and
CVE Binary Tool from immutable container digests, and compares the components
against the upstream SQLCipher, SQLite, and OpenSSL security notices. Scanner
silence alone is not acceptance. An applicable unresolved advisory blocks the
release.

The exact provider source accepts
`SqliteStorageProvider<C, ConnectionRef: Borrow<rusqlite::Connection>>`.
A `rusqlite::Transaction` dereferences to its connection, so a provider
constructed from `&*transaction` and application statements execute inside the
same caller-owned transaction. This type-level argument is not build evidence.
K3's independent review must reproduce it, and the build must commit the exact
dependency graph plus a compile-and-rollback integration test before the
transaction claim is accepted.

OpenMLS storage values use a Citadel codec identified in database metadata as
`citadel-openmls-json-v1`. Its private `CitadelOpenMlsJsonCodecV1`
implementation pins
`serde_json = { version = "=1.0.150", default-features = false, features =
["std"] }`. Serialization first converts the value to `serde_json::Value`, whose
object maps remain ordered because the `preserve_order` feature is disabled,
then writes compact JSON bytes. Deserialization rejects malformed or trailing
non-whitespace input. This deterministic compatibility format is never used as
an identifier, signature input, or hash input. A committed schema-complete
golden corpus pins the bytes that v1 writes and proves they round-trip after
restart. The exact dependency and feature set remain locked until an explicit
storage migration changes them.

The v1 identifier is bound to `openmls` 0.8.1, `openmls_traits` 0.5.0,
`openmls_sqlite_storage` 0.2.0, and that provider's storage schema. Its
committed corpus is schema-complete: it covers every OpenMLS storage entity,
enum variant, optional shape, and boundary representation used by Citadel.
Changing any bound OpenMLS crate or storage schema requires a new codec
identifier and migration even when the existing corpus happens to remain
byte-identical.

The codec identifier and bound-version tuple are written before the first
OpenMLS record. An unknown or newer identifier or version tuple fails closed.
A future codec migration must retain the old decoder, decode every old provider
row, encode it with the new codec, and update the identifier last in one
transaction. There is no trial-decoding or silent fallback between codecs.

This intentionally replaces PLAN §4's `sqlx` choice for the local encrypted
client store. OpenMLS's storage trait is synchronous, and its maintained
synchronous provider uses `rusqlite`. Using its `sqlx` provider would drive
asynchronous calls with `tokio::task::block_in_place`, require a multithreaded
Tokio runtime in every client call, and complicate the transaction boundary.
The PostgreSQL service stack remains on `sqlx`.

No plaintext SQLite database is accepted or converted in place. A standard
SQLite header at the configured path is an error. Import and encrypted backup
remain M8 work behind a separate accepted design.

### 2. Database encryption key and OS credential-store contract

The database encryption key is exactly 32 uniformly random bytes generated
once through the OpenMLS RustCrypto provider's OS-backed random source. It is
not derived from a password, account identifier, device key, machine
identifier, or other low-entropy input. Citadel encodes it only at the
SQLCipher boundary as the canonical `x'<64 lowercase hex characters>'` raw-key
form and passes that fixed representation through SQLCipher's programmatic key
API. SQLCipher therefore bypasses its passphrase KDF. There is no
application-level KDF, and SQLCipher retains responsibility for its internal
page and HMAC key schedule.

At rest, the database encryption key exists only as a binary secret in the
current OS user's credential store:

| Platform | Required backend | Contract |
|---|---|---|
| Windows | Windows Credential Manager | Per-user generic credentials written with `CRED_PERSIST_LOCAL_MACHINE`; enterprise roaming is forbidden |
| macOS | Keychain Services | Non-synchronizing generic-password items in the login keychain |
| Linux | freedesktop Secret Service | Items in the user's default collection; a locked collection may prompt |

The Windows adapter calls `CredReadW`, `CredWriteW`, and `CredDeleteW` through
`windows-sys` 0.61.2 because `keyring` 3.6.3 hard-codes
`CRED_PERSIST_ENTERPRISE`. macOS uses `keyring` 3.6.3's concrete Apple-native
builder. Linux pins
`keyring = { version = "=3.6.3", default-features = false, features =
["sync-secret-service", "crypto-rust"] }` and uses its concrete synchronous
Secret Service builder. The `crypto-rust` feature is mandatory so the D-Bus
session uses Diffie-Hellman encryption; negotiation of the Secret Service
`Plain` algorithm is rejected. The code never constructs `keyring`'s default
builder, which can fall back to its mock store when a native feature is absent.
Target-specific dependencies and constructors make unsupported targets a
compile error. Linux keyutils, environment variables, files, command output,
enterprise-roaming Windows credentials, and process-memory-only stores are not
fallbacks. A credential store double exists only under test configuration.
Release CI identifies and exercises the concrete backend on each supported
desktop target.

The Windows read adapter places the `CredReadW` result in an RAII owner that
constructs a checked mutable slice over `CredentialBlob`, applies
`zeroize::Zeroize` to that slice, and only then calls `CredFree` on every exit
path, including malformed lengths and copy failures. This avoids depending on
a Windows wipe binding that `windows-sys` 0.61.2 does not expose. A valid
32-byte blob is copied directly into a `Zeroizing` owner and no ordinary
`Vec<u8>` or `String` intermediate is created. The macOS and Linux adapters
likewise wrap returned binary secrets in `Zeroizing` immediately.

The v1 desktop supports one local device profile per OS user. One fixed,
non-empty service identity and three distinct possible per-profile item
identities address the database encryption key, account identity signing seed,
and device signing seed. Every profile has the database encryption key and,
after enrollment, its device signing seed. The profile that creates and retains
the account identity has its account identity signing seed; an additional
device profile does not copy that seed merely to satisfy this store contract.
Each present value is exactly 32 independently generated random bytes. No value
is derived from another. This preserves PLAN §7 F1's credential-store contract
for private keys while keeping the database encryption key independent.
OpenMLS private state remains inside the encrypted database.

Unavailable, locked without successful user authorization, missing, duplicate,
malformed, or inaccessible credential-store entries fail closed:

- if the final database, staging database, and database encryption key entry
  are all absent, first-run initialization may create them;
- if the final database exists and its database encryption key entry is
  absent, Citadel returns `StoreKeyMissing` and never generates a replacement;
- if the database encryption key entry exists while both database paths are
  absent, Citadel returns `StoreStateInconsistent` and requires an explicit
  reset or recovery action;
- a wrong key, corrupt database, duplicate database encryption key entry, or
  unsupported SQLCipher format is an error and never triggers an empty-store
  reset.

Account and device signing entries follow registration and enrollment
lifecycle, not store creation. An operation that requires a signer not held by
that profile either uses the explicit cross-device authorization protocol
defined for the operation or returns a typed missing, malformed, locked, or
inaccessible-credential error. It never generates a replacement, copies an
account seed to an additional device, or recovers a seed from the database.

Before inspecting those states, Citadel opens one fixed lock file read-write
without truncation and calls `std::fs::File::try_lock` for an OS-enforced
exclusive profile lock. Rust 1.95 is the workspace minimum, so this stable
standard-library primitive needs no lock dependency. The handle remains owned
through the actor lifetime and profile destruction. Lock content is empty,
lock loss on process death is automatic, `TryLockError::WouldBlock` becomes
`StoreAlreadyOpen`, and every other lock error is preserved as an I/O failure.
Unix opens the lock with no-follow semantics. Windows opens it without reparse
point traversal. Both platforms validate the opened handle as a regular file
inside the fixed platform application-data directory. The database, staging
path, SQLite sidecar files, and lock must resolve inside that directory and
must not traverse symbolic links or Windows reparse points. This prevents two
processes or a path substitution from racing credential-store and file
operations.

First-run creation uses one fixed staging path beside the final database,
opened with exclusive creation and per-user permissions. Citadel creates,
keys, migrates, and integrity-checks the staging database, closes it with no
live journal, synchronizes the file, writes and reads back the
database encryption key entry, then installs the file. Unix uses `rename`
followed by a parent-directory sync. Windows uses `MoveFileExW` with
`MOVEFILE_WRITE_THROUGH`. The final path must not already exist.

Startup handles every interrupted state:

| Final | Staging | Database encryption key entry | Result |
|---|---|---|---|
| absent | absent | absent | clean first creation |
| absent | present | absent | remove the unreadable orphan staging file, then create |
| absent | absent | present | `StoreStateInconsistent`; no automatic deletion |
| absent | present | present | validate with the database encryption key entry, recover any hot journal, close and sync, then finish installation |
| present | any | absent | `StoreKeyMissing`; no replacement key |
| present | absent | present | validate and open the final database |
| present | present | present | validate the final database, then remove the stale staging file |

Any failed validation, sync, credential-store operation, or installation
returns a typed error and preserves evidence for explicit recovery. A crash may
leave ciphertext and a rollback journal, but never a usable plaintext database.

### 3. Connection hardening

> **Amended by Amendment 1 §A.6.** `PRAGMA cipher_status` does not exist on the
> staged bundle (verified absent from the shipped 4.5.7 amalgamation). The open
> sequence's codec verification is respecified there. Every other setting in this
> section, including the readback requirement and the abort-on-failure rule,
> stands unchanged.

One store actor owns one SQLite connection on a dedicated blocking thread. It
serializes all access without blocking Tauri's UI thread or requiring a Tokio
runtime. Every connection is keyed through SQLCipher's programmatic key API
before any schema access, using only the canonical raw-key representation
described above. The open sequence verifies the exact SQLCipher version,
an active encryption codec through `PRAGMA cipher_status`, successful encrypted
schema access, and a schema sentinel. It runs
`cipher_integrity_check` during first creation, before and after a pending
migration, after recovery of an unclean shutdown, and during explicit
maintenance. SQLCipher page authentication still fails an ordinary open when
an accessed page is corrupt; a full scan is not imposed on every startup.

The actor sets and reads back these required settings:

- `SQLITE_DBCONFIG_DEFENSIVE = ON`;
- `cipher_memory_security = ON`;
- `secure_delete = ON`;
- `foreign_keys = ON`;
- `journal_mode = DELETE`;
- `synchronous = FULL`;
- `temp_store = MEMORY`; and
- `trusted_schema = OFF`.

Failure to enable or verify a required setting aborts opening the store.
SQLCipher query logging remains disabled. The raw key and its temporary hex
representation use zeroizing owners while opening the database. SQLCipher also
holds key material for the connection lifetime; closing the actor is required
before profile destruction.

These controls do not claim to defeat a live process compromise, OS paging,
hibernation capture, or raw-device forensic recovery. They protect stored
database files and reduce recoverable logical remnants. `journal_mode = DELETE`
is deliberate: WAL would retain prior encrypted page images that remain
readable to an attacker who later obtains the current database encryption key.
In rollback-journal mode, deleting the journal is SQLite's commit point. A hot
journal after a crash is rolled back before the store becomes available.

### 4. Persistence boundary

The encrypted database persists all state needed to resume safely after a
process restart:

- every record required by the OpenMLS storage trait, including group state,
  message secrets, pending commits and proposals, KeyPackages, HPKE private
  keys, and epoch key pairs;
- public local device and credential metadata;
- the highest accepted `(tree_size, root_hash)` signed KT tree head required by
  ADR-0001's anti-rollback rule;
- conversations and decrypted local messages;
- delivery sequence cursors, receipts, and deduplication state;
- exact pending commit, Welcome, and application-message wire bytes whose
  transport outcome is not final;
- the idempotency key and state needed to retry each pending transmission
  without advancing the MLS state again;
- a monotonic per-profile operation sequence, an unpruned operation-ID ledger,
  and a bounded ring of the 256 most recent state-changing operation outcomes.
  The ledger stores each caller-supplied operation ID, sequence, operation kind,
  and canonical request fingerprint. A retained outcome also stores its typed
  result and exact returned bytes needed to reconcile an indeterminate commit
  result.

M2 does not claim general offline catch-up or a user-facing outbox. Those remain
M5. The M2 pending-transmission rows exist only because persisting an advanced
sender ratchet or pending commit without the exact bytes to retry would be
restart-unsafe.

Plaintext message content, conversation titles, sender metadata, and the
OpenMLS secret records are inside SQLCipher. The account identity and device
signing seeds exist only in their distinct OS credential-store entries.
SQLite sidecar files use the same SQLCipher protection and may not contain an
application-defined plaintext copy. Database filenames, file sizes,
modification times, and the existence of a Citadel profile remain visible.

In memory, Citadel holds only the current operation's loaded group, signer
objects loaded from the credential store, returned plaintext, and the open
connection. Secret byte buffers use zeroizing owners where their types permit
it and are never logged. Closing the profile drops signer objects as well as
the database connection.

### 5. Transaction and crash contract

The encrypted database is the source of truth. A long-lived in-memory
`MlsGroup` is not authoritative across operations.

Every state-changing public core operation requires an opaque 16-byte
`OperationId` that its caller generates with the OS CSPRNG and retains before
entering the actor. The actor never assigns or substitutes it. A transport
adapter retains the ID with its delivery or pending-transmission identity; an
interactive caller that intends to retry after restart must retain the ID
before submitting the mutation. Every state-changing core operation then runs
synchronously inside one `rusqlite::Transaction` with
`TransactionBehavior::Immediate` on the actor's connection. The transaction
constructs a borrowing OpenMLS storage provider, loads the group, performs the
MLS operation, writes the matching application record, and commits before
returning success. There is no network wait while a transaction is open.

The atomic units are:

- create or join: OpenMLS group state plus conversation and pending delivery;
- send: advanced sender state plus plaintext local row, exact ciphertext, and
  idempotency key;
- receive application message: advanced receiver state plus the deduplicated
  plaintext row;
- receive commit: merged group state plus received sequence metadata;
- accept KT advancement: verified signed tree head plus the monotonic
  anti-rollback checkpoint;
- prepare update or membership change: pending OpenMLS state plus the exact
  outbound bytes and proposed epoch;
- confirm or abort: pending-operation removal plus the corresponding OpenMLS
  merge or rollback state.

Before mutation, the actor serializes the operation kind and every typed
request field with the same pinned deterministic JSON rules as the storage
codec, prefixes `citadel-operation-request-v1`, and hashes those bytes with
SHA-256 through the existing RustCrypto primitive. Its schema-complete corpus
is part of the codec evidence. An existing operation ID with a different kind
or fingerprint returns `OperationIdConflict` without mutation.

Each atomic unit allocates the next sequence and writes the operation-ID ledger
row and outcome in the same transaction. The exclusive actor means no other
mutation can allocate that sequence while its outcome is unresolved. The actor
may prune only outcome payloads older than the newest 256 after a later
operation commits; it never prunes operation-ID ledger rows or decreases the
high-water sequence. Increment is checked; `u64::MAX` returns
`OperationSequenceExhausted` without mutation. Retrying a retained operation ID
with the same fingerprint returns the stored outcome. A matching ledger row
whose outcome was pruned returns `OperationReceiptExpired` and is never
applied again. Delivery deduplication and pending-transmission identities
remain in their domain rows and are not pruned by the outcome ring.

Any SQL, serialization, or OpenMLS error before the SQLite commit point rolls
back the transaction and discards the loaded group object. A commit error has
an indeterminate outcome: the actor discards the group, closes and reopens the
connection, lets SQLite recover, and reconciles the durable group epoch,
operation receipt, idempotency key, and stored wire bytes before reporting an
outcome. A matching receipt returns its stored typed result and exact bytes; an
absent receipt proves the transaction did not apply because the receipt and
mutation share one atomic unit. If recovery cannot read or validate the
receipt, the actor returns `StoreOutcomeIndeterminate` and requires
reconciliation. It never blindly repeats an MLS mutation.

Transport reads committed pending bytes after the transaction.
Acknowledgement removes or confirms them in a new transaction. Startup uses
the same reconciliation path rather than silently accepting, regenerating, or
dropping pending operations.

Application migrations and the upstream OpenMLS provider migrations use
separate, named migration-history tables in the same encrypted database.
Migrations run only after successful key and integrity verification. They are
transactional, immutable after release, and fail without resetting user state.
A database with a newer unsupported schema or codec fails closed.

### 6. State deletion and security claims

Citadel has two different deletion cases, and tests must not substitute one for
the other.

Forward secrecy here means that current persisted MLS secret state cannot
decrypt a previously unseen old-epoch ciphertext after obsolete epoch state is
deleted. It does not make deliberately retained decrypted message history
unreadable. A compromise that obtains the database encryption key can read
those local message rows. This precise boundary replaces PLAN §9 M2's broad
"past messages unreadable" wording; local-history expiry or per-message
cryptographic deletion requires a separate accepted retention design.

**MLS forward-secrecy deletion.** Successful epoch transitions cause OpenMLS to
delete obsolete message and epoch secrets through its storage trait in the same
transaction that persists the new state. For the M2 process-crash contract, a
successful commit return on a live filesystem has removed the rollback
journal. An injected process stop before that point leaves either the old state
directly or a hot journal that startup rolls back before opening the store. A
snapshot is eligible for the forward-secrecy assertion only after commit
returns, or after recovery confirms the new epoch and no live rollback journal.
There is no test-only checkpoint or cleanup step.

An I/O or power failure at or after the logical commit point is indeterminate
until reopen and recovery. This ADR does not claim that rollback-journal
deletion is metadata-durable against an offline disk image captured during an
unrecovered power loss, especially on Windows. The M2 evidence injects process
stops, not power cuts. It asserts only a quiescent live-filesystem snapshot or
a recovered snapshot whose durable epoch is known.

Group creation and join configuration explicitly set `max_past_epochs` to zero
instead of inheriting the OpenMLS default. An OpenMLS upgrade must not silently
expand retained epoch history. Loading a group whose persisted configuration
retains past epochs fails closed unless a later accepted ADR changes this
contract. `secure_delete` reduces logical stale-page recovery, but does not
promise physical erasure on SSD, copy-on-write, backup, or journaled
filesystems.

The M2 forward-secrecy test gives the attacker a copy of the current encrypted
database, every SQLite sidecar file, and the correct database encryption key.
Before the epoch transition, the sender creates an old-epoch application
ciphertext that the target has never processed. A pre-transition control
snapshot must decrypt it. After the transition has returned success, the test
copies the live files without special cleanup, reopens them through the real
provider, and first decrypts a never-processed current-epoch ciphertext as a
positive control. It then bypasses application deduplication and proves the old
ciphertext fails as `ProcessMessageError::ValidationError`, containing
`ValidationError::UnableToDecrypt`, containing
`MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)`.
A parser error, epoch comparison in application code, or replay rejection is
not sufficient. Merely deleting the database encryption key does not satisfy
this test.

The post-compromise security (PCS) test uses the opposite direction. It gives
the attacker the pre-update database snapshot and its correct database
encryption key, then applies and persists an honest self-update. The captured
state receives the exact public self-update commit through the production
receive path before it is asked to decrypt future ciphertext. The current-state
control merges the commit and derives a fixed-label exporter secret before it
decrypts a never-before-processed post-update ciphertext.

If OpenMLS refuses the captured member's own commit because the snapshot lacks
the pending update secret, the test must assert that exact typed failure, but
that rejection is not the PCS oracle. A test-only extractor decodes the
captured provider snapshot into its prior init secret and every retained HPKE
private key. An independent differential driver parses the exact public commit
with `mls-spec` 2.0.1 and uses `mls-rs-crypto-awslc` 0.25.0 to attempt every
UpdatePath ciphertext with every captured key. It must recover no path secret
and therefore no commit secret or post-update exporter output. A control given
the honest pending self-update secret state derives the fixed-label exporter
output and matches the reopened OpenMLS group.

A second mirror uses `mls-rs` 0.55.2 as the updater. It clones that updater's
complete pre-update group state, creates a detached self-update commit, withholds
the returned `CommitSecrets` from the captured clone, and gives them only to the
honest control. The captured clone consumes the same public commit as far as
the independent API permits and must neither match the control exporter output
nor decrypt the future ciphertext. This models the captured updater rather
than an unrelated honest member. An epoch-number mismatch alone is not
sufficient evidence.

The oracle crates are exact CI-validation dependencies, not production or
runtime dependencies. The secret extractor is unavailable outside test builds
and a release-graph check rejects it. A committed corpus separates captured
attacker inputs from honest-only commit secrets and contains the TLS-wire
transcript, fixed test keys, exporter output, and ciphertext. A reproducible
driver regenerates both the exact OpenMLS differential case and the `mls-rs`
mirror, then byte-compares the corpus in CI. If the extractor or either pinned
oracle cannot implement this contract for the selected ciphersuite, the PCS
evidence and M2 close are blocked rather than replaced with a self-referential
test.

**Local profile destruction.** An explicit destructive operation first
closes the actor, then attempts deletion of the distinct database encryption
key, device signing seed, and account identity signing seed entries. It
attempts every deletion and reports a structured partial-failure result rather
than stopping at the first error. It then removes the database, every SQLite
sidecar file, and the staging file, reporting each residual path. The profile
lock is released last. Local profile destruction succeeds only when all
three credentials and all files are confirmed absent; an already absent entry
or path satisfies that condition. Confirmed loss of the database encryption
key is cryptographic erasure of residual database files, not a claim that the
filesystem overwrote every block.

The application never intentionally serializes the database encryption key or
signing seeds to server storage, telemetry, logs, application crash reports, or
the database itself. OS crash dumps may capture live process memory and remain
outside this at-rest boundary. A disk-file attacker without the database
encryption key entry gets ciphertext, file metadata, and the SQLCipher salt,
but no SQLite schema, plaintext messages, or MLS secrets.

SQLCipher page authentication detects modification, not freshness. Replacing
the complete live database and sidecar set with a valid older encrypted
snapshot also rolls back the database-resident KT checkpoint and is not
detected in M2. A historical snapshot combined with later compromise of the
unchanged database encryption key reveals the plaintext and MLS secrets that
snapshot contained. The forward-secrecy evidence therefore gives the attacker
the confirmed current post-transition snapshot and key; it does not claim
security after the attacker captured pre-deletion state. A future rollback
resistance claim requires an external monotonic freshness anchor and a separate
accepted design.

An attacker able to read the unlocked OS credential store or process memory
can open the current store and may obtain the signing seeds; local encryption
does not claim otherwise. A backup containing both the database and its live
database encryption key is equivalent to current client state.

## Alternatives considered

1. **`sqlx` plus OpenMLS's `sqlx` provider.** Rejected for the client. Its
   synchronous OpenMLS surface drives asynchronous `sqlx` internally with
   `block_in_place`, requires a multithreaded Tokio runtime, and adds an
   unnecessary runtime constraint to Tauri and future FFI callers.
2. **The stock bundled SQLCipher source.** ~~Rejected.~~ **Reversed by
   Amendment 1 §A: this is the M2 choice.** The original rejection reasoning is
   retained for the record: "The compatible `libsqlite3-sys` release embeds
   SQLCipher 4.5.7; the current Rust release embeds 4.14.0. Neither is SQLCipher
   4.17.0, which incorporates current upstream SQLite fixes." K3's review
   established that this is a freshness preference rather than the named
   advisory §1's own gate requires, so the rejection did not meet this ADR's
   stated bar. See Amendment 1 §A.
3. **Forking the OpenMLS provider onto current `rusqlite`.** Rejected for M2.
   Its `refinery` migration dependency is also tied to the older `rusqlite`
   line, so this requires owning both provider and migration-engine changes.
   Revisit when OpenMLS publishes a compatible provider or an advisory forces
   the upgrade.
4. **Hand-written OpenMLS storage implementation.** Rejected. The upstream
   provider already implements the large versioned storage trait, so a local
   duplicate would create avoidable secret-deletion and upgrade risk.
5. **Plain SQLite plus per-column encryption.** Rejected. It would require a
   new encryption format, nonce and key management, leave schema and indexes
   visible, and violate INV-10's prohibition on custom cryptographic
   mechanisms.
6. **Password-derived database encryption key.** Rejected. V1 has no account
   password, recovery is explicitly deferred, and a random key in the OS
   credential store has full entropy without an application KDF.
7. **OS full-disk encryption only.** Rejected. It does not protect a copied
   database or application-data backup that has been separated from the OS
   credential store.
8. **Silent memory-only or plaintext fallback.** Rejected. It would create a
   downgrade, make restart behavior nondeterministic, and make the M2 evidence
   meaningless.
9. **Deleting the key as the forward-secrecy test.** Rejected. That proves
   database encryption key separation, not that a compromise of current MLS state cannot
   decrypt past traffic.

## Consequences

- Positive: M2 gains durable OpenMLS state, crash-safe transport retry, local
  plaintext storage protected at rest, and independently testable key
  destruction.
- Positive: OpenMLS and application state share one transaction and one
  established SQLite implementation.
- Positive: the desktop graph uses current SQLCipher without forking OpenMLS's
  secret-state implementation. **Amended by Amendment 1 §A:** M2 uses the stock
  bundled SQLCipher 4.5.7, not the current release. The "without forking" half
  becomes stronger, not weaker — M2 forks nothing at all.
- Negative: desktop builds compile bundled SQLCipher and vendored OpenSSL,
  increasing build time and binary size.
- **Negative (Amendment 1 §B.3): a vendored OpenSSL C codebase enters
  `citadel-core`, the one process holding plaintext, MLS secrets, and signing
  seeds.** This requires narrowing `deny.toml`'s graph-wide `openssl-sys` ban to
  `wrappers = ["libsqlite3-sys"]`. Accepted knowingly; the alternatives
  (LibTomCrypt, macOS-only CommonCrypto, or a hand-written OpenMLS storage
  provider) are worse. Reasoning and the conditions that would reopen it are in
  Amendment 1 §B.3 and §B.4.
- Build-time dependencies: the pinned platform C toolchain, Perl,
  `openssl-src` and OpenSSL sources, platform Configure target and options,
  GNU Make or `nmake.exe`, and NASM 3.02 on Windows x86-64. SQLCipher and
  OpenSSL are built from the pinned source graph. **Amended by Amendment 1 §A.1:**
  M2 pins none of these itself; it takes `openssl-src`'s own build contract. The
  pinned-builder program moves to the separate ADR of §A.2.
- Runtime dependencies: the native OS credential service. No external
  SQLCipher or OpenSSL installation is required.
- CI-validation dependencies: an isolated runner user, Windows Credential
  Manager on Windows, a temporary login keychain on macOS, and a real D-Bus
  session plus Secret Service implementation on Linux. Test-created credential
  items and keychains are removed after the conformance run. The PCS
  interoperation job also builds the exact `mls-rs` and AWS-LC development
  graph; neither ships in the client.
- Cargo audit and deny cover the Rust graph. The native manifest, SBOM,
  digest-pinned scanners, upstream security-notice comparison, and committed
  license texts cover the linked C sources.
- ~~Negative: Citadel owns a narrow `libsqlite3-sys` source overlay. Every
  SQLCipher or OpenMLS upgrade must regenerate it, reproduce its provenance,
  rebuild all three desktop targets, and rerun the store evidence.~~
  **Removed by Amendment 1 §A: M2 owns no overlay.** This consequence returns
  only if the separate reproducibility ADR of §A.2 is later accepted.
- Negative: Linux desktop use requires a running Secret Service implementation
  and may require an unlock prompt. Headless Linux is unsupported for the
  production local encrypted client store and fails closed.
- Negative: only the newest 256 generic operation outcomes remain replayable.
  Older known operation IDs fail as expired instead of returning their
  original result. Their compact ID and fingerprint ledger rows remain until
  profile destruction so they cannot be reapplied; domain-specific delivery
  deduplication remains separately durable.
- Negative: local encryption does not defend an unlocked client, a process
  compromise, or a backup that includes both the database and its encryption
  key.
- Follow-up: M5 extends the minimal pending-transmission table into the full
  offline outbox and sync-cursor model.
- Follow-up: M8 designs encrypted export and recovery. It must not copy the
  live database encryption key into a backup.

## Evidence

The build must provide these named tests using real SQLCipher and the real
OpenMLS provider. Test-only credential-store doubles may inject success and
error states; production backend conformance runs per supported desktop OS.

> **Amended by Amendment 1 §A.7.** No test below is renamed, removed, or
> weakened. Three of them change pinned *values* only, because M2 ships
> SQLCipher 4.5.7 rather than 4.17.0:
> `store_release_uses_only_pinned_sqlcipher`,
> `store_and_oracle_dependencies_pass_advisory_and_license_policy`, and
> `store_epoch_transition_removes_obsolete_secret_bytes`.

- **`store_first_create_is_atomic_and_credential_store_failures_fail_closed`** covers
  every state-table row and injects a process stop after each create, sync,
  database encryption key credential, and installation step. It also races two
  processes and rejects symbolic-link and reparse-point substitutions.
  Separate cases prove missing account and device signing entries fail the
  operations that require them without mutating the store.
- **`store_provider_and_application_share_one_transaction`** compiles the exact
  borrowing provider type, mutates both schemas, and proves injected failure
  commits or rolls back both together. Commit-error cases reopen and reconcile
  the durable operation receipt without repeating an MLS mutation. A parent
  harness retains the caller-generated operation ID, stops the client after
  commit but before result delivery, restarts it, and proves the same ID returns
  the committed result without reapplying the request. The test fills and wraps
  the 256-outcome ring, proves the high-water sequence never decreases,
  preserves every operation-ID ledger row, returns retained results exactly,
  rejects the same ID with changed request fields, expires pruned outcomes
  without reapplying them, and fails closed at `u64::MAX`.
- **`store_codec_v1_roundtrips_golden_corpus_and_migrates`** byte-compares the
  schema-complete committed `citadel-openmls-json-v1` corpus, reopens and
  decodes every value, migrates to a test v2 codec in one transaction, and
  rejects unknown identifiers, version tuples, and unversioned OpenMLS
  dependency changes.
- **`store_release_uses_only_the_target_native_credential_backend`** runs in
  release CI on Windows, macOS, and Linux, identifies the concrete adapter, and
  proves the mock and unsupported backends cannot be selected. Linux asserts
  the Secret Service session negotiates Diffie-Hellman and rejects `Plain`.
  Windows instruments the API boundary to prove every credential blob is
  zeroed before `CredFree`; all targets prove returned secret owners are
  zeroizing types.
- **`store_release_uses_only_pinned_sqlcipher`** builds all three desktop
  targets from clean environments, proves a single `rusqlite` and
  `libsqlite3-sys` graph, inspects the linked artifacts, reads back SQLCipher
  4.17.0 and the required compile options, and rejects system-library input.
- **`store_release_excludes_secret_evidence_paths`** builds the production
  feature graph on all desktop targets and proves the PCS secret extractor,
  fixed test keys, oracle crates, and `crypto-debug` capability are absent from
  the dependency graph and linked artifacts.
- **`store_and_oracle_dependencies_pass_advisory_and_license_policy`** covers
  `rusqlite` 0.32.1, `refinery` 0.9.2, `libsqlite3-sys` 0.30.1, SQLCipher
  4.17.0, the resolved vendored OpenSSL chain, and the CI-only `mls-rs`
  0.55.2, `mls-spec` 2.0.1, and `mls-rs-crypto-awslc` 0.25.0 oracle graph. It
  verifies the Rust policy separately from the native manifest and CycloneDX
  SBOM, requires both pinned native scanners to run, and fails on an applicable
  unresolved upstream security notice or missing license text.
- **`store_rejects_plaintext_wrong_key_corruption_and_unverified_cipher`**
  proves a plaintext SQLite file, random wrong key, tampered page, missing
  SQLCipher capability, or unsupported schema never opens or resets.
- **`store_disk_copy_without_key_contains_no_canary_plaintext`** copies the
  database and every SQLite sidecar file after storing message and MLS
  canaries; byte scans, standard SQLite, and a random SQLCipher key recover none
  of them.
- **`store_restart_restores_group_and_pending_transmission_exactly_once`**
  kills and reopens between MLS mutation and transport acknowledgement, retries
  the exact persisted bytes and idempotency key, and advances no ratchet twice.
- **`store_restart_preserves_kt_anti_rollback_checkpoint`** accepts a larger
  consistent signed tree head, restarts, then rejects shorter and forked heads
  without advancing the current persisted checkpoint.
- **`store_whole_file_rollback_boundary_is_explicit`** restores a valid older
  database and sidecar set with the correct key, proves SQLCipher opens it and
  the database-resident KT checkpoint rolls back with it, and prevents any API
  or documentation from reporting page authentication as snapshot freshness.
- **`store_receive_is_atomic_with_plaintext_and_mls_state`** injects failures
  before and during commit and proves neither the message row nor receiver
  state can land alone.
- **`store_profile_destruction_revokes_keys_and_reports_residual_files`** verifies
  closed connections, attempted deletion of all three credential entries, all
  known SQLite sidecar files, and structured partial-failure and
  residual-ciphertext reporting.
- **`post_restart_snapshot_proves_mls_forward_secrecy`** supplies the correct
  database encryption key and current persisted provider state, asserts
  `max_past_epochs` is zero, proves a pre-transition control snapshot decrypts
  a never-processed old-epoch ciphertext, injects process stops on both sides
  of the rollback-journal commit point, recovers indeterminate outcomes,
  decrypts a current-epoch positive-control ciphertext after reopen, and
  requires the exact `TooDistantInThePast` error chain for the old ciphertext.
- **`store_epoch_transition_removes_obsolete_secret_bytes`** captures the exact
  pre-transition OpenMLS secret rows, including values larger than one page.
  Before the transition, a positive control must recover every captured value
  from decrypted pages. After the transition, the same evidence build uses the
  pinned SQLCipher/SQLite source with `SQLITE_ENABLE_DBPAGE_VTAB` plus the
  matching upstream `dbdata.c` recovery extension to reconstruct B-tree cells,
  overflow chains, and recoverable deleted records. Both logical provider
  queries and the reconstructed page corpus must contain none of the obsolete
  values. If the pre-transition recovery control misses a value, the test is
  invalid rather than green.
- **`post_restart_update_proves_post_compromise_security`** persists a
  self-update, restarts both peers, feeds the public commit to the captured
  pre-update state, and proves current state decrypts a never-processed future
  ciphertext. It also checks the exact missing-update-secret failure when
  applicable, extracts every captured old HPKE key, and drives the exact commit
  through the pinned `mls-spec` parser and AWS-LC differential oracle. The
  independent `mls-rs` captured-updater mirror and honest-secret control must
  agree with the production outcome, and CI byte-compares both committed
  corpora.
- **`store_migrations_are_encrypted_transactional_and_monotonic`** proves fresh
  and upgrade paths, schema and codec rollback on injected failure,
  newer-schema rejection, and absence of plaintext temporary databases.
- **`store_clean_open_does_not_run_a_full_integrity_scan`** instruments a
  representative large store and proves ordinary startup reads the sentinel
  without `cipher_integrity_check`; separate benchmark output records the full
  maintenance-scan cost.
- **`store_hot_path_latency_is_measured_on_all_desktop_targets`** records p50,
  p95, and p99 clean-open, send, receive, and commit latency with real
  SQLCipher, `FULL`, `DELETE`, and `secure_delete` settings on Windows, macOS,
  and Linux. The committed benchmark recipe fixes the dataset at 20 groups and
  10,000 local messages, separates cold and warm runs, records runner hardware
  and filesystem, and samples at least 1,000 hot operations. No latency claim
  or regression budget is accepted until those outputs exist and charge
  reviews them.

## Amendment 1 (ACCEPTED, charge, 2026-07-26): stage the SQLCipher overlay; name the `deny.toml` narrowing

K3's independent design review returned **CHANGES** with two blocking findings
(`docs/issues/009-adr-0007-store-design-review.md`, merged `9ca9317`). Both are
folded here. This amendment is **doc-only and decides no new design**: it removes
scope, records a config change the body silently required, and corrects premises.

**Not reopened, and this amendment must not be read as weakening any of it.** K3
verified and approved the store design as written, and §§2 through 6 stand: the
key handling and OS credential-store contract, the fail-closed startup state
machine, the transaction and crash contract, the deletion semantics, and the
forward-secrecy and PCS evidence package. §D below lists the five items K3
specifically verified, which survive this amendment intact.

### A. F1 — the overlay fails this ADR's own gate; stage it out of M2

**The gate.** §1 states its own rule for the SQLCipher choice: "a relevant
advisory blocks this choice and requires a provider upgrade." Alternative 2
rejected the stock bundle not on that rule but on a freshness line — 4.5.7 "is
not 4.17.0." Everything expensive in the body hangs off that one line: the
repository-local `libsqlite3-sys` patch, the vendored-OpenSSL Configure
transcripts, pinned NASM, the immutable three-OS builder matrix, and byte
comparison of regenerated amalgamations and bindings.

**The evidence, from K3's review.** Named CVEs against the bundle's embedded
SQLite 3.45.3 do exist (CVE-2025-3277 / CVE-2025-29087, CVE-2025-6965,
CVE-2025-7709, CVE-2025-29088, CVE-2026-11822/11824). None is applicable in this
usage: each requires attacker-controlled SQL, an attacker-crafted database file,
FTS5 tables, `DEFENSIVE` off, or app-side C-API misuse. `cargo-audit` over the
ADR's exact pinned graph, run under this repo's own config, returned zero
advisories on any crate this ADR introduces. **So the gate is not triggered, and
the overlay is not authorized by this ADR's own stated standard.**

**Decision: M2 ships on the stock bundle.**

#### A.1 What M2 builds

`rusqlite` 0.32.1 with `bundled-sqlcipher-vendored-openssl`, resolving
`libsqlite3-sys` 0.30.1 — **unpatched**. The following are verified directly
against the shipped amalgamation in that exact crate, not taken on report:

| Property | Value | Where verified |
|---|---|---|
| SQLCipher version | `4.5.7`, `community` build | `sqlcipher/sqlite3.c:106612`, `:106616` |
| Embedded SQLite | `3.45.3` | `sqlcipher/sqlite3.h`, `SQLITE_VERSION` |
| Crypto provider | OpenSSL, selected by **compiled default** | `sqlcipher/sqlite3.c:106599-106603` |

The third row matters and is not obvious: `libsqlite3-sys`'s build script never
passes `-DSQLCIPHER_CRYPTO_OPENSSL`. SQLCipher defines it itself whenever no
other provider macro is set, and on the `bundled-sqlcipher-vendored-openssl`
path the build script's CommonCrypto branch is unreachable on every target,
macOS included. §1's OpenSSL-provider pin therefore holds on the stock bundle,
but it holds *by default rather than by pin*, so it must be **proved by readback**
(`PRAGMA cipher_provider`) rather than assumed.

**Removed from M2 scope:** the repository-local `libsqlite3-sys` patch and the
4.17.0 amalgamation; the pinned OpenSSL Configure target/option vectors and
their transcripts; the pinned NASM 3.02 artifact and `OPENSSL_RUST_USE_NASM`
requirement; the pinned Perl/C-toolchain/Make/VS-Build-Tools builder images and
their digests; and byte-comparison of regenerated artifacts. `openssl-src` is
still in the graph — it is what `vendored` builds — but M2 takes whatever that
crate's own pinned build contract produces instead of dictating it.

#### A.2 What becomes its own ADR

The reproducibility and provenance program moves out whole, to be justified on
its own merits if and when charge wants it. **It must be argued on the
properties it buys, not on a version number.** Stating the honest case for it,
since staging is not a claim it is worthless: SQLCipher 4.7.0+ adds keyspec
obfuscation, fast overwrite of freed memory, and `PRAGMA cipher_status`. Those
are real defense-in-depth. A future ADR that names *them* as the reason is a
proportionate argument; a freshness line that smuggles in indefinite maintenance
of a fork of a C crypto library's build glue is not.

#### A.3 What stays in M2: the tripwire

The **lightweight** native manifest and native scan stay, and staging makes them
more important rather than less, because they are now the only mechanism that
would detect an advisory that genuinely does become relevant to this usage. They
cost a CI job, not a fork. The staged manifest records, for the *stock* bundle:
the SQLCipher version and build string as read back from the shipped library,
the embedded SQLite version, the vendored OpenSSL version as resolved by
`openssl-src`, and the exact license texts for SQLCipher, SQLite, and OpenSSL.
The reproducible job generates a CycloneDX SBOM, runs OSV-Scanner and CVE Binary
Tool from immutable container digests, and compares components against upstream
SQLCipher, SQLite, and OpenSSL security notices. **Scanner silence alone is not
acceptance, and an applicable unresolved advisory blocks the release** — both
rules carry over from §1 unchanged.

#### A.4 The applicability finding, recorded — with one leg of it corrected

The analysis above is recorded here so that a future reader inherits the
reasoning rather than having to re-derive it. **One correction, found while
verifying the staged build and not present in K3's review:** K3's applicability
argument for the two FTS5 CVEs cites "the build omits FTS5," which was true of
the overlay and is **false of the stock bundle**. `libsqlite3-sys` 0.30.1
compiles `-DSQLITE_ENABLE_FTS5` unconditionally (`build.rs:129`), and staging
removes the patch that turned it off.

The conclusion still holds, but it now rests on fewer legs and the record must
say so honestly:

- **CVE-2025-7709** additionally requires an attacker-crafted database file.
  SQLCipher page HMAC under the database encryption key forecloses that, and the
  store never opens a foreign database (§2 rejects a plaintext SQLite header
  outright).
- **CVE-2026-11822** additionally requires `DBCONFIG_DEFENSIVE` off. §3 pins it
  ON with readback and aborts the open if it cannot be verified.
- **Both** additionally require reaching an FTS5 table through attacker-influenced
  SQL. Citadel constructs all of its SQL in application code, attacker data
  arrives only as bound parameters, and the schema contains no FTS5 table — the
  feature is compiled in but never instantiated.

That is still a sound foreclosure. It is a materially weaker one than "the
feature is not in the binary," and pretending otherwise is exactly the kind of
prose-outrunning-code this lane has been caught on before.

#### A.5 The compile-flag pins §1 can no longer make

Staging removes the patch, so Citadel no longer controls `libsqlite3-sys`'s
build script and cannot set §1's flag vector. Each pin is resolved explicitly
rather than left to drift. Verified against `build.rs` in the pinned crate:

| §1 pin | Stock bundle | Resolution |
|---|---|---|
| `SQLITE_HAS_CODEC` | set (`:144`) | **Holds.** |
| `SQLITE_THREADSAFE=1` | set (`:136`) | **Holds.** |
| `SQLCIPHER_CRYPTO_OPENSSL` | not passed; compiled default | **Holds by default.** Prove by `PRAGMA cipher_provider` readback (A.1). |
| `SQLITE_TEMP_STORE=3` | `=2` (`:144`) | **Accepted at 2.** `2` already defaults temp storage to memory, and §3's per-connection `temp_store = MEMORY` pin with readback delivers the guarantee on the actor's only connection. No security property is lost. |
| `SQLITE_EXTRA_INIT` / `SQLITE_EXTRA_SHUTDOWN` | absent | **Pin dropped.** These are mandatory only from SQLCipher 4.7.0; 4.5.7 initializes correctly without them, which is the configuration the stock crate ships and exercises. |
| remove FTS5 | `-DSQLITE_ENABLE_FTS5` set (`:129`) | **Cannot be honored.** Accepted per A.4. |
| remove FTS3 | `-DSQLITE_ENABLE_FTS3` (`:127`) and `-DSQLITE_ENABLE_FTS3_PARENTHESIS` (`:128`) set | **Cannot be honored.** Same class as FTS5, accepted on the same reasoning: the schema creates no FTS table of any kind and the application issues no attacker-influenced SQL. Recorded because this table is the standing reference for what the staged bundle compiles, and a reader checking a future FTS3 advisory against an incomplete table would get the wrong answer. (docs/issues/011 N2, closed by the store build.) |
| `SQLITE_OMIT_LOAD_EXTENSION` | `-DSQLITE_ENABLE_LOAD_EXTENSION=1` set (`:131`) | **Cannot be honored.** Mitigated at runtime, below. |

**Extension loading, since the compile-time pin is gone.** The capability is
compiled in but inert by default: SQLite refuses the `load_extension()` SQL
function unless the `SQLITE_LoadExtFunc` connection flag is set
(`sqlite3.c:135068-135071`), and that flag is set only by an explicit
`sqlite3_enable_load_extension` call (`:142378`). Citadel therefore pins three
things instead: it **never** calls `rusqlite`'s `load_extension_enable` or the
underlying C API on any connection; §3's existing `trusted_schema = OFF` pin
blocks a schema-embedded invocation; and the open sequence asserts the flag is
off. A build in which extension loading can be enabled fails closed.

**The mechanism of that assertion, named (docs/issues/011 N1, closed by the
store build).** The sentence above originally said "the open sequence asserts
the flag is off" without saying how, and an unnamed assertion is not evidence.
The mechanism is a **behavioral probe**, not an inspection:
`citadel_core::store::open::probe_extension_loading_is_refused` runs
`SELECT load_extension(<a name that does not exist>)` on the live connection at
the end of every open and requires the call to fail with exactly
`not authorized`. That string is not incidental — it is what `loadExt` returns
when `SQLITE_LoadExtFunc` is clear (`sqlcipher/sqlite3.c:135068-135074`) — and
requiring it is what separates "refused" from "reached the loader and could not
find the file", which is what a *set* flag would produce. The probe is wired
into `store_release_uses_only_pinned_sqlcipher`, and the open aborts if it does
not hold.

A supporting fact, which strengthens the position but deliberately does **not**
replace the probe: `rusqlite` 0.32.1 gates `load_extension_enable` behind a
`load_extension` feature, and declares no default features at all, so the safe
enabling API is not compiled on this graph. The probe's value is that it keeps
holding if a future dependency change quietly enables that feature.

**Standing rule for the staged flag set:** the pins above are what M2 asserts,
and `store_release_uses_only_pinned_sqlcipher` reads them back from the built
artifact. A flag the shipped bundle does not honor is a **build failure and an
escalation**, never a silently skipped check.

#### A.6 §3's open sequence on 4.5.7

`PRAGMA cipher_status` is SQLCipher 4.12.0+ and is **absent from the shipped
4.5.7 amalgamation** (verified: zero occurrences in `sqlcipher/sqlite3.c`, where
`cipher_version`, `cipher_provider`, `cipher_integrity_check`, and
`cipher_memory_security` are all present). §3's "active encryption codec through
`PRAGMA cipher_status`" is replaced, for the staged build, by this sequence —
which is not weaker, only differently sourced:

1. `PRAGMA cipher_version` returns exactly the pinned bundle version (`4.5.7`).
2. `PRAGMA cipher_provider` returns the expected OpenSSL provider — this is what
   now carries A.1's "codec is active and is the provider we think it is."
3. **Successful encrypted schema access plus the schema sentinel**, already
   mandatory in §3. This is the load-bearing codec proof and is
   version-independent: a connection whose codec is not active, or is keyed
   wrongly, cannot read the schema at all.
4. `cipher_integrity_check` at first creation and at the other points §3 already
   names. Available since SQLCipher 4.2.0, so unaffected by staging.

§3's rule that failure to enable **or verify** any required setting aborts
opening the store applies to every step above. If a pragma this sequence depends
on turns out to be unavailable on the shipped bundle, that is a build failure
and an escalation under AGENTS.md rule 8 — not a skipped step.

#### A.7 Evidence

**No evidence test is renamed, removed, or weakened.** Only pinned values move:

- `store_release_uses_only_pinned_sqlcipher` reads back `PRAGMA cipher_version`
  = **4.5.7** and `PRAGMA cipher_provider` = OpenSSL, asserts the A.5 flag table
  — including the behavioral `load_extension()` probe named in A.5 and the FTS3
  and FTS5 rows, which it asserts are **present** rather than absent, because
  A.4's foreclosure rests on "compiled but unreachable" and a bundle that
  actually removed them would need the record corrected rather than quietly
  improved — and still proves a single `rusqlite` / `libsqlite3-sys` graph with
  no system-library input.
- `store_and_oracle_dependencies_pass_advisory_and_license_policy` covers
  SQLCipher **4.5.7** and embedded SQLite **3.45.3** in place of 4.17.0, against
  the lightweight manifest and SBOM of A.3.
- `store_epoch_transition_removes_obsolete_secret_bytes` builds its
  `SQLITE_ENABLE_DBPAGE_VTAB` + `dbdata.c` recovery harness against the **shipped
  4.5.7** source. The technique is version-portable; the build recipe follows
  whichever bundle ships. Its pre-transition positive control is unchanged and
  still invalidates the test if it misses a value.

### B. F2 — the `deny.toml` collision, and admitting vendored OpenSSL as a named consequence

#### B.1 The collision the body never named

`bundled-sqlcipher-vendored-openssl` resolves as
`["bundled-sqlcipher", "openssl-sys/vendored"]`, putting
`libsqlite3-sys 0.30.1 → openssl-sys 0.9.117` in the graph. `deny.toml` bans
`openssl-sys` **graph-wide**. K3 reproduced the failure against this repo's real
config with cargo-deny 0.20.2:

```
error[banned]: crate 'openssl-sys = 0.9.117' is explicitly banned
```

**As written, this ADR could not build under this project's own CI, and never
said so.** That is the finding. It is independent of F1: dropping
`vendored-openssl` removes `openssl-sys` but then requires a system OpenSSL to
link against, which does not exist on the Windows target of this ADR's own
release matrix. Vendored OpenSSL is required either way.

#### B.2 The fix

K3's proven one-line narrowing, applied to `deny.toml`'s `[bans] deny` list:

```toml
{ name = "openssl-sys", wrappers = ["libsqlite3-sys"], reason = "SQLCipher page codec links vendored OpenSSL via libsqlite3-sys; not a TLS stack" }
```

`openssl-sys` remains banned everywhere else in the graph; it is permitted only
when pulled in by `libsqlite3-sys`. `native-tls` stays banned unconditionally.
`.cargo/audit.toml` needs no change, and the license allowlist already covers the
new surface. Both suppression files are load-bearing and cargo-audit runs first,
so this is recorded as a change to `deny.toml` **only**.

#### B.3 The accepted consequence — recorded as a decision, not a config edit

This is where the amendment does more than restate the review, and deliberately
so. **The narrowing is not merely a lint tweak, and must not land as one.**

The ban's stated intent, in `deny.toml`'s own comment, is that "TLS is
rustls-only; the native-TLS/openssl stack must never enter the graph." The
narrowing preserves the TLS half of that intent exactly: no TLS stack enters, and
the OpenSSL build serves SQLCipher's page codec and nothing else. But it does
admit **a vendored OpenSSL C codebase into `citadel-core`** — the one process in
this system that holds plaintext, MLS secrets, and signing seeds. That is a real
increase in unsafe-language attack surface in the highest-value process, and this
ADR accepts it knowingly.

**Accepted, for these reasons:**

- The alternatives are worse. SQLCipher's non-OpenSSL crypto backends are
  LibTomCrypt (a less-scrutinized C codebase — a downgrade, not an escape) and
  CommonCrypto (macOS only, so it cannot serve the release matrix). Avoiding
  SQLCipher entirely means hand-writing an OpenMLS storage provider, which
  Alternative 4 already rejected for sound reasons: the upstream provider
  implements a large versioned storage trait, and a local duplicate would create
  avoidable secret-deletion and upgrade risk in exactly the code that deletes
  MLS secrets.
- OpenSSL is not new attack surface of an exotic kind. It is the most-reviewed
  implementation of the primitives SQLCipher needs, it is reachable only through
  SQLCipher's page codec on local files this process already owns, and it parses
  no network input in this role. INV-10 is untouched: no Citadel-authored crypto
  primitive is introduced, and MLS group cryptography remains entirely OpenMLS's.
- The build is vendored and pinned, so the version is ours to advance, and A.3's
  native manifest plus OSV scan is precisely the tripwire for an OpenSSL advisory
  that does apply.

**Why this is written out at length.** In six months someone will read a ban
comment saying the openssl stack must never enter the graph, run `cargo tree`,
see OpenSSL in the graph, and have to determine whether they are looking at a
decision or at a drift. This section exists so that question has an answer in the
repository. The `reason` string in `deny.toml` should point here.

#### B.4 What would reopen this

The narrowing is scoped to `libsqlite3-sys`. Any of the following is a new
decision, not covered by this acceptance: a second wrapper added to the
`wrappers` list; `openssl-sys` arriving through any path other than SQLCipher's
page codec; `native-tls` entering the graph at all; or a service crate (as
opposed to `citadel-core`) acquiring an OpenSSL dependency, which would also be
an AGENTS.md rule 6 crypto-confinement question.

### C. Non-blocking corrections from the review

- **`max_past_epochs` phrasing (§6).** §6 says the pin is set "instead of
  inheriting the OpenMLS default," which implies the current default is non-zero.
  In openmls 0.8.1 the default is **already 0**. The explicit pin is correct and
  **stays** — its value is fail-closed protection against an upstream default
  change, which §6's next sentence already states. Read the sentence as "instead
  of relying on the OpenMLS default."
- **`dbdata.c` recovery build recipe.** Folded into A.7.

### D. Verified by K3's review; unchanged by this amendment

Recorded explicitly because a scope-reducing amendment is exactly where approved
work gets damaged by accident:

1. The forward-secrecy test's exact error chain —
   `ProcessMessageError::ValidationError` → `ValidationError::UnableToDecrypt` →
   `MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)`
   — reproduced against openmls 0.8.1 source. Including the subtle part: the
   `PublicMessage` path diverges to `ValidationError::NoPastEpochData`, which
   confirms §6 is right to demand an old-epoch **application** ciphertext.
   Unchanged.
2. The `max_past_epochs = 0` pin with fail-closed behavior on OpenMLS default
   drift. Unchanged (see §C for the phrasing note only).
3. The PCS design's refusal to substitute a self-referential test, **including
   that it blocks M2 close rather than degrading the evidence**. Unchanged.
4. The shared-transaction type argument (`Transaction: Deref<Target = Connection>`
   satisfying `ConnectionRef: Borrow<Connection>`), and that it is a type-level
   argument requiring
   `store_provider_and_application_share_one_transaction` as build evidence.
   Unchanged.
5. The keyring `CRED_PERSIST_ENTERPRISE` justification — keyring 3.6.3 hard-codes
   it at `src/windows.rs:246`, so the direct `windows-sys` adapter with
   `CRED_PERSIST_LOCAL_MACHINE` is warranted. Unchanged.

### E. The separate acceptance-criterion decision — DECIDED

§6 narrows PLAN §9 M2's broad "past messages unreadable" wording to a
persisted-state boundary. K3 flagged this and correctly declined to decide it, as
did the core lane. AGENTS.md reserves acceptance-criterion changes to charge, so
this was held out of the ADR acceptance deliberately and remained open after both
reviews.

**DECIDED (charge, 2026-07-26): the narrowing is accepted.** charge instructed the
advisor to record it ("Accept. Make the decision."). Recorded here as an explicit
delegation rather than an advisor decision, because the authority is charge's under
the roster clause and delegating it is charge's to do; the advisor holds no
standing power to change an acceptance criterion.

The criterion now reads as PLAN §9 M2 states it, amended in the same commit. The
substance of what was accepted, stated plainly so a later reader is not misled:

- **What forward secrecy means here.** Current persisted MLS secret state cannot
  decrypt a previously unseen old-epoch ciphertext after obsolete epoch state is
  deleted. This is proved against an attacker holding the database, every SQLite
  sidecar file, **and** the correct database encryption key.
- **What it does not mean.** Deliberately retained decrypted message history stays
  readable to anyone holding that key. Making retained history unreadable is a
  *retention* feature (local-history expiry or per-message cryptographic deletion),
  not forward secrecy, and it requires its own accepted design.
- **Why this is a correction rather than a weakening.** MLS forward secrecy is a
  property of key material, not of a local plaintext archive. The original PLAN
  wording described a property MLS does not provide and no comparable messenger
  provides. The narrowed criterion is the testable claim, and it is tested against a
  strictly stronger attacker than the original wording implied.

This is a user-facing property claim, so it is also stated in the README's security
posture, not only here.

## Amendment 2 (ACCEPTED, charge, 2026-08-14): corrections from the store build

This amendment records what the build disproved in the accepted text. It does
not change an acceptance criterion or waive missing evidence.
`docs/issues/012-adr-0007-build-findings.md` preserves the source-level
investigation. Charge accepted this amendment after K3 completed its blocking
review. It takes effect when PR #69 merges; the accepted body on `main` remains
controlling until then.

### A. Persisted past-epoch configuration is checked through its stored representation

Section 6's fail-closed requirement stands, but its assumed OpenMLS API does
not exist. In openmls 0.8.1, `MlsGroup::configuration()` returns
`&MlsGroupJoinConfig`; that type's `max_past_epochs` field is private and it has
no public getter. The similarly named public getter belongs to
`MlsGroupCreateConfig`.

The required check therefore serializes the loaded join configuration with the
pinned codec and reads `max_past_epochs` from that representation. This is the
representation persisted in the provider's `join_group_config` row. A loaded
configuration with a non-zero value fails with
`PastEpochRetentionRejected`; one whose field cannot be extracted fails with
`PastEpochRetentionUnreadable`. Malformed persisted data that OpenMLS cannot
load fails earlier through `GroupError::Mls`. No unreadable case defaults to
zero.

This replaces only the accessor premise. The explicit zero pin, the
post-restart assertion, and the requirement to reject widened persisted state
are unchanged.

### B. Operation-ledger scope and two in-profile exceptions

Section 5's statement that every state-changing public operation requires an
`OperationId` was too broad. The ledger governs these nine mutation methods:
`create_group`, `join_from_welcome`, `add_members`, `send`, `receive`,
`prepare_self_update`, `confirm_self_update`, `abort_self_update`, and
`accept_kt_head`. Profile lifecycle
operations (`open`, `close`, and `destroy`) instead follow Sections 2 and 6:
startup reconciliation is idempotent, close releases resources, and destroy
returns a structured residual report. None is an operation-ledger unit.

Within an open profile, the M2 build has two additional state-changing public
methods that are explicit ledger exceptions.

#### B.1 KeyPackage generation

`LocalStore::new_key_package` changes provider state but is transactional and
deliberately unledgered in the M2 implementation. Every successful invocation
generates a fresh KeyPackage and commits its private material before returning.
If the process stops after that commit but before response delivery, the caller
cannot recover the returned public package and the private material can remain
in the encrypted store.

This is a documented M2 exception only. No automatic KeyPackage replenisher or
reaper may ship against this API. The production lifecycle must satisfy every
requirement below before automatic replenishment or cleanup is enabled.

1. Generation has a durable operation identity. One generation operation ID
   maps to one RFC 9420 `KeyPackageRef`, the exact serialized public
   KeyPackage, its init-key identity, and its private provider records. While
   the result payload is retained, a retry of the same operation ID returns the
   same package. After that payload expires, the same ID returns a typed expired
   result and never generates fresh material. The compact operation ID,
   fingerprint, package reference, and terminal state remain until profile
   destruction. Only a new operation ID generates fresh material.
2. The canonical package identifier is RFC 9420's `KeyPackageRef`, computed
   from the exact TLS-encoded KeyPackage. `LocalStore` derives it from the
   validated generated object and separately records the `cipher_suite` field.
   It enforces uniqueness of the exact encoded HPKE `init_key` across every
   KeyPackage created by this device, including live records and local
   tombstones, without scoping that uniqueness to a cipher suite. The opaque
   service derives the package reference from the exact submitted bytes under
   Citadel's pinned v1 cipher suite through a canonical
   `citadel-proto` encoding helper and the existing SHA-256 facade; it does not
   hand-roll the reference input or claim to validate or deduplicate init keys.
   A future multi-cipher-suite pool cannot preserve that opaque derivation and
   requires a separately accepted protocol and crypto-confinement design.
3. Before any publication request can leave the process, the client durably
   records `publish_pending`, including the exact package bytes and a stable
   publication request ID. A missing or lost publication response leaves the
   package in `publish_pending`; it never makes the package unpublished or
   eligible for cleanup.
4. Publication is idempotent under the device and publication request ID.
   Repeating a request returns the original per-package result and rejects
   changed bytes. The service enforces package-reference uniqueness across live
   rows and retained tombstones. An aggregate pool size is not reconciliation
   evidence; the response or a linearizable reconciliation operation identifies
   every package's status.
5. Before a fetch can leave the requesting device, that device durably records
   an authenticated request ID and every request field. It retries or reconciles
   only under that ID until the exact response is durably recorded. The service
   executes the request idempotently: the first execution atomically selects
   and marks the exact per-device packages as handed out and stores the complete
   response. A retry returns those same package bytes; changed request fields
   conflict. Handed-out and indeterminate packages count against replenishment
   limits. A lost response therefore cannot burn another package under a new
   request ID or drive automatic replenishment into unbounded retained private
   state.
6. The service distinguishes `available` from `handed_out`. It atomically and
   irreversibly records `handed_out` before public package bytes can be returned
   to a fetcher. A lost fetch response does not return the package to
   `available`. An active, expired, or indeterminate reservation or lease is
   not deletion evidence. Once bytes might have crossed the service boundary,
   the package is `handed_out` unless a separately accepted protocol makes
   lease expiry enforceable at every consumption path.
7. Server handout is not MLS consumption. MLS consumption occurs only when
   this device successfully processes a Welcome using that package. The
   lifecycle transition and removal of its private provider material occur in
   the same local transaction as the successful join, with a durable terminal
   tombstone.
8. A reaper may delete private KeyPackage material only when one of these
   positive predicates is durably established:

   - publication was never attempted: the package is still `generated`, has no
     publication outbox record, and the before-send rule makes it impossible
     for public bytes to have left the process;
   - an atomic service retirement operation serialized against publication and
     fetch, prevented every future fetch, and returned a per-package result
     proving the package was never handed out; that result is persisted locally
     before deletion; or
   - successful local MLS consumption has already made the private material
     obsolete in the same transaction.

   `publish_pending`, `published`, `available`, `leased`, `handed_out`, an
   indeterminate network result, elapsed wall-clock time, and pool age are all
   deletion blockers. Failure to contact or reconcile with the service
   preserves the private material.
9. A fetched or possibly fetched package that never reaches successful local
   consumption remains retained. Bounded cleanup of that state requires a
   separate accepted design with a cryptographically bound use deadline
   enforced by every Welcome submission and join path. Lease expiry, local age,
   or a server assertion alone is not such a deadline.
10. Local tombstones retain the generation operation ID, publication request
    ID, package reference, exact init key, and terminal fingerprint until local
    profile destruction. Service tombstones retain the publication request ID,
    fetch request ID, package reference, and terminal state. The service has no
    init-key identity and does not infer local profile destruction. It may
    remove its tombstones only through an authenticated service-side device
    retirement protocol that first revokes future device requests, serializes
    against publication and fetch, and returns a durable retirement
    acknowledgment. Result payloads may expire after the complete KeyPackage
    validity and retry horizon, but the compact tombstones do not expire before
    those explicit local and service terminal events. A late retry must never
    recreate, republish, reissue, or consume the package twice.

Until this lifecycle is implemented and independently tested, the accepted
operation-ledger guarantee excludes `new_key_package`, orphan cleanup remains
disabled, and no claim is made that the current behavior is production pool
management.

The former `new_key_package` source comment explained the M2 choice by claiming
that replay must generate fresh material. That production premise is
superseded by the lifecycle above: generation replay is safe only when
publication and fetch are also idempotent. The amendment was proposed as a
doc-only change and deliberately did not alter source before charge accepted
the correction.

#### B.2 Pending-transmission acknowledgment

`LocalStore::acknowledge_transmission` deletes a pending outbox row without a
new `OperationId`. Its input is the exact 16-byte idempotency key of that
transmission, and `DELETE ... WHERE idempotency_key = ?` is naturally
idempotent: the first successful call removes at most one row and every retry
has the same terminal outcome. It returns no replay payload and makes no MLS
mutation.

This is an explicit exception to Section 5's universal wording, not a read
operation. If acknowledgment later acquires a result that must be replayed or
side effects beyond the keyed delete, it must join the operation ledger before
that expansion ships.

### C. Windows path containment has a residual race

Section 2 overstated a cross-platform guarantee. The
`SQLITE_OPEN_NOFOLLOW` behavior cited in this repository is in
`libsqlite3-sys` 0.30.1's `sqlcipher/sqlite3.c`, the amalgamation Citadel
actually compiles. That flag is effective through the Unix VFS and inert
through the Windows VFS.

The profile lock is opened with reparse-point traversal disabled and is
revalidated through its open handle. Its containment check is therefore tied
to the locked object. The database, staging file, rollback journals, and other
sidecars are validated by path before open. Lock-first ordering narrows the
window, but a same-user attacker able to rename or replace those paths can race
validation and open on Windows. M2 does not close that TOCTOU window.

If accepted, this is an explicit residual limitation, not a claim that path
validation is race-free. Closing it requires a handle-relative or
identity-revalidated database-open design and separate review.

### D. Incoming application messages and commits share one ledger domain

The build finding that motivated a split was withdrawn. RFC 9420 places
`content_type` in cleartext in `PrivateMessage`, and OpenMLS exposes it before
decryption through `MlsMessageIn::try_into_protocol_message()` and
`ProtocolMessage::content_type()`.

The M2 implementation nevertheless keeps one incoming MLS wire-message
operation domain. Its fingerprint covers the group identifier and the complete
MLS wire bytes, so an identical retry has the same identity whether it later
yields an application message or a commit. Parsing once inside the store
transaction also avoids a caller-side parse followed by an actor-side parse
that could disagree. The outcome remains tagged as received application or
merged commit.

This replaces Section 5's two incoming atomic-unit labels with one semantic
unit: process one incoming MLS wire message. The current
`ReceiveApplication`/`receive_application` discriminator is a legacy label for
that shared domain, not a claim that every input is application content. Its
source comment must use the wire-message rationale above rather than the
withdrawn "caller cannot know" premise.

### E. SQLCipher pragma order and result type are normative

`PRAGMA cipher_memory_security = ON` must run before `PRAGMA key`, because
keying allocates the codec state whose allocator policy the readback reports.
The readback is SQL text, not an integer column. The hardened open sequence
must read the text, parse it strictly, and require `1`; changing either the
order or the result type makes a correctly configured store fail its startup
check.

### F. Lock content is not an invariant

Section 2's statement that lock content is empty applies only to a lock file
Citadel created. Existing lock files are opened read-write without truncation,
so existing content is preserved. Citadel neither reads nor trusts that
content. Mutual exclusion and containment come from the file lock and
handle-based validation only.

### G. Live native credential backend evidence covers Linux; full release conformance covers zero platforms

Section 2 requires release-CI evidence on Windows, macOS, and Linux. Every
repository CI job still runs on `ubuntu-latest`; there are no Windows or macOS
jobs. In
[run 30325276041](https://github.com/Phew/Citadel/actions/runs/30325276041),
the first Linux native credential backend job ran four credential tests: the
two tests that do not write to Secret Service passed, while both live write
tests failed with `Locked("Secret Service: no result found")`.
The result is consistent with the fresh runner having no default collection
for `gnome-keyring-daemon --unlock` to unlock. The job did not inspect the
daemon's collection state directly, so the exact provisioning cause remains
unproven by that failed run alone.

K3's `b772c0f` repair supplied a non-empty throwaway keyring password and added
a fail-fast `ReadAlias("default")` gate. In
[run 30329679255](https://github.com/Phew/Citadel/actions/runs/30329679255),
the gate resolved
`/org/freedesktop/secrets/collection/login`, then all four credential tests
passed, including both live Secret Service tests, and the complete workflow
finished successfully. That is new live Linux native credential backend
evidence.

A local Windows terminal run was reported passing the native Credential
Manager round-trip tests, but its output was not committed or published and it
is not the required release matrix. Run 30329679255 also used the default test
profile; it did not prove the production release graph excludes the credential
double and unsupported backends, or that all returned secret owners are
zeroizing types. Therefore live native credential backend execution covers
Linux, but the
full `store_release_uses_only_the_target_native_credential_backend` contract
still covers **zero of three platforms**. This amendment does not weaken the
three-platform requirement, treat a local run as CI, or mark the criterion
complete. The production release-conformance jobs remain open on all three
targets.

## Primary sources

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [OpenMLS SQLite storage provider 0.2.0 API](https://docs.rs/openmls_sqlite_storage/0.2.0/openmls_sqlite_storage/struct.SqliteStorageProvider.html)
- [rusqlite 0.32.1 transaction API](https://docs.rs/rusqlite/0.32.1/rusqlite/struct.Transaction.html)
- [serde_json 1.0.150 API](https://docs.rs/serde_json/1.0.150/serde_json/)
- [mls-rs 0.55.2 crate and feature graph](https://docs.rs/crate/mls-rs/0.55.2)
- [mls-rs group commit and exporter API](https://docs.rs/mls-rs/0.55.2/mls_rs/group/struct.Group.html)
- [mls-spec 2.0.1 data structures and compatibility layer](https://docs.rs/crate/mls-spec/2.0.1)
- [libsqlite3-sys 0.30.1 wrapper and stock SQLCipher source](https://docs.rs/crate/libsqlite3-sys/0.30.1/source/)
- [OpenMLS storage-provider model](https://blog.openmls.tech/posts/2024-09-04-v0_6-release/)
- [SQLCipher 4.17.0 release and upstream SQLite fixes](https://www.zetetic.net/blog/2026/07/08/sqlcipher-4.17.0-release/)
- [SQLCipher 4.17.0 source tag](https://github.com/sqlcipher/sqlcipher/releases/tag/v4.17.0)
- [SQLCipher design and encrypted temporary-file behavior](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher key, memory-security, and integrity APIs](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [SQLCipher random-key and platform-keystore guidance](https://www.zetetic.net/sqlcipher/database-key-material/)
- [SQLite security advisories](https://sqlite.org/cves.html)
- [OpenSSL vulnerabilities](https://openssl-library.org/news/vulnerabilities/)
- [openssl-src 300.6.1+3.6.3 build contract](https://docs.rs/crate/openssl-src/300.6.1%2B3.6.3)
- [NASM 3.02 release artifacts](https://www.nasm.us/pub/nasm/releasebuilds/3.02/)
- [keyring-rs platform backends and failure considerations](https://docs.rs/crate/keyring/3.6.3/source/README.md)
- [keyring-rs Secret Service crypto feature graph](https://docs.rs/crate/keyring/3.6.3/source/Cargo.toml)
- [keyring-rs 3.6.3 Windows enterprise-persistence implementation](https://docs.rs/crate/keyring/3.6.3/source/src/windows.rs)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services/)
- [Windows generic-credential storage and local-machine persistence](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- [Windows durable file move](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [Rust `File::try_lock` contract](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
- [freedesktop Secret Service locking contract](https://specifications.freedesktop.org/secret-service/latest/unlocking.html)
- [SQLite secure-delete behavior](https://sqlite.org/pragma.html#pragma_secure_delete)
- [SQLite rollback-journal commit and recovery](https://sqlite.org/atomiccommit.html)
- [SQLite `sqlite_dbdata` recovery extension](https://sqlite.org/recovery.html)
