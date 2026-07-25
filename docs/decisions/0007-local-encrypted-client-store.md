# ADR-0007: Local encrypted client store

- **Status:** PROPOSED
- **Date:** 2026-07-24
- **Deciders:** charge (required for ACCEPTED); independent design review: K3 pending
- **Invariants touched:** INV-1, INV-2, INV-4, INV-5, INV-9, INV-10
- **Related:** plans/PLAN.md §§3, 4, 6, 9 M2, and 13; ADR-0001 §5;
  ADR-0005 §4; OpenMLS 0.8.1
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
2. **The stock bundled SQLCipher source.** Rejected. The compatible
   `libsqlite3-sys` release embeds SQLCipher 4.5.7; the current Rust release
   embeds 4.14.0. Neither is SQLCipher 4.17.0, which incorporates current
   upstream SQLite fixes.
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
  secret-state implementation.
- Negative: desktop builds compile bundled SQLCipher and vendored OpenSSL,
  increasing build time and binary size.
- Build-time dependencies: the pinned platform C toolchain, Perl,
  `openssl-src` and OpenSSL sources, platform Configure target and options,
  GNU Make or `nmake.exe`, and NASM 3.02 on Windows x86-64. SQLCipher and
  OpenSSL are built from the pinned source graph.
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
- Negative: Citadel owns a narrow `libsqlite3-sys` source overlay. Every
  SQLCipher or OpenMLS upgrade must regenerate it, reproduce its provenance,
  rebuild all three desktop targets, and rerun the store evidence.
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

## Primary sources

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
