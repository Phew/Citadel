//! ADR-0007 Evidence, for the tests that can run without release CI.
//!
//! Names match the ADR's Evidence list so a reader can diff this file against
//! it. Four named tests are **not** here, and pretending otherwise would be the
//! defect this project keeps catching:
//!
//! - `store_release_uses_only_the_target_native_credential_backend`, and the
//!   three-desktop-target half of `store_release_uses_only_pinned_sqlcipher`,
//!   need Windows, macOS, and Linux release runners. This repository's CI is
//!   `ubuntu-latest` only. The single-target half of the SQLCipher test —
//!   version, provider, the Amendment 1 §A.5 flag table, and the extension
//!   probe — does run here, against the real linked artifact.
//! - `store_and_oracle_dependencies_pass_advisory_and_license_policy` is a
//!   native-manifest, SBOM, and pinned-scanner job, not a Rust test.
//! - `post_restart_update_proves_post_compromise_security` needs the `mls-rs` /
//!   `mls-spec` / AWS-LC differential oracle, which nobody has built yet.
//! - `store_hot_path_latency_is_measured_on_all_desktop_targets` needs the
//!   three-target benchmark recipe.
//!
//! Everything else below runs against real SQLCipher and the real OpenMLS
//! provider, on a temporary profile directory with a credential-store double.

use super::codec::{CitadelOpenMlsJsonCodecV1, CODEC_BOUND_VERSIONS, CODEC_ID};
use super::credentials::double::{Call, CredentialStoreDouble, Injected};
use super::credentials::{CredentialStore, SecretItem};
use super::error::StoreError;
use super::evidence::CapturedSnapshot;
use super::ledger::{OperationId, RETAINED_OUTCOMES};
use super::lifecycle::StartupState;
use super::open::{
    open_hardened, probe_extension_loading_is_refused, OpenIntent, EXPECTED_CIPHER_PROVIDER,
    EXPECTED_CIPHER_VERSION,
};
use super::paths::ProfilePaths;
use super::provider::StoreProvider;
use super::schema::{meta_key, read_metadata, APP_SCHEMA_VERSION, SCHEMA_SENTINEL};
use super::{LocalStore, OperationOutcome};
use crate::crypto::EphemeralProvider;
use crate::group::{DmGroup, GroupError, ReceiveOutcome};
use crate::identity::DeviceIdentity;
use crate::testing::{make_identity, AllowList};
use citadel_proto::ids::GroupId;
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_sqlite_storage::Codec;
use std::sync::Arc;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

struct Fixture {
    dir: TempDir,
    credentials: Arc<CredentialStoreDouble>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            credentials: Arc::new(CredentialStoreDouble::new()),
        }
    }

    fn paths(&self) -> ProfilePaths {
        ProfilePaths::at_root(self.dir.path().join("profile"))
    }

    fn open(&self) -> Result<LocalStore, StoreError> {
        LocalStore::open(
            self.paths(),
            self.credentials.clone() as Arc<dyn CredentialStore>,
        )
    }
}

fn local_identity() -> Arc<DeviceIdentity> {
    Arc::new(make_identity().identity)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn protocol_message(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact_bytes(bytes)
        .expect("deserialize")
        .try_into_protocol_message()
        .expect("protocol message")
}

// ---------------------------------------------------------------------------
// store_first_create_is_atomic_and_credential_store_failures_fail_closed
// ---------------------------------------------------------------------------

#[test]
fn store_first_create_is_atomic_and_credential_store_failures_fail_closed() {
    // --- row 1: clean first creation -------------------------------------
    let fixture = Fixture::new();
    let store = fixture.open().expect("clean first creation");
    let paths = store.paths().clone();
    assert!(paths.database().exists(), "the final database is installed");
    assert!(
        !paths.staging().exists(),
        "the staging file is gone after installation"
    );
    assert!(
        fixture
            .credentials
            .contains(SecretItem::DatabaseEncryptionKey),
        "the key entry exists after creation"
    );
    let (reads, writes, _deletes) = fixture.credentials.call_counts();
    assert_eq!(writes, 1, "the key is written exactly once");
    assert!(reads >= 2, "written AND read back before installation");
    store.close().expect("close");

    // --- row 6: reopen an existing store ---------------------------------
    fixture
        .open()
        .expect("reopen existing")
        .close()
        .expect("close");

    // --- the lock: a second open of the same profile fails closed --------
    let first = fixture.open().expect("first holder");
    let second = fixture.open();
    assert!(
        matches!(second, Err(StoreError::StoreAlreadyOpen(_))),
        "a second holder must fail closed, got {second:?}"
    );
    first.close().expect("close");

    // --- row 5: database present, key entry absent -----------------------
    let fixture = Fixture::new();
    fixture.open().expect("create").close().expect("close");
    fixture
        .credentials
        .delete(SecretItem::DatabaseEncryptionKey)
        .expect("drop the key entry");
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::StoreKeyMissing)),
        "a database with no key must never get a replacement key, got {result:?}"
    );
    assert!(
        fixture.paths().database().exists(),
        "and the database is left exactly as it was"
    );

    // --- row 3: key entry present, no database ---------------------------
    let fixture = Fixture::new();
    fixture.paths().prepare().expect("prepare");
    fixture
        .credentials
        .seed(SecretItem::DatabaseEncryptionKey, [0x5A; 32]);
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::StoreStateInconsistent(_))),
        "a key with no database requires explicit recovery, got {result:?}"
    );
    assert!(
        fixture
            .credentials
            .contains(SecretItem::DatabaseEncryptionKey),
        "and nothing was deleted automatically"
    );

    // --- row 2: orphan staging with no key entry -------------------------
    let fixture = Fixture::new();
    let paths = fixture.paths();
    paths.prepare().expect("prepare");
    std::fs::write(paths.staging(), b"unreadable orphan").expect("seed orphan");
    let store = fixture
        .open()
        .expect("the orphan staging file is removed, then creation proceeds");
    assert!(paths.database().exists());
    assert!(!paths.staging().exists());
    store.close().expect("close");

    // --- row 7: a stale staging file beside a good database --------------
    std::fs::write(paths.staging(), b"stale").expect("seed stale staging");
    let store = fixture
        .open()
        .expect("open existing and clear stale staging");
    assert!(
        !paths.staging().exists(),
        "the stale staging file is removed"
    );
    store.close().expect("close");

    // --- injected credential failures all fail closed --------------------
    for injected in [
        Injected::Unavailable,
        Injected::Locked,
        Injected::Inaccessible,
        Injected::Duplicate,
    ] {
        let fixture = Fixture::new();
        fixture.credentials.inject(
            SecretItem::DatabaseEncryptionKey,
            Call::Write,
            injected.clone(),
        );
        let result = fixture.open();
        assert!(
            matches!(result, Err(StoreError::Credential(_))),
            "{injected:?} on write must fail closed, got {result:?}"
        );
        // The final database must NOT exist. The key is written and read back
        // before installation precisely so this state is unreachable.
        assert!(
            !fixture.paths().database().exists(),
            "{injected:?}: a store must not be installed when its key could not be stored"
        );
    }

    // A malformed existing entry is refused rather than truncated or replaced.
    let fixture = Fixture::new();
    fixture.credentials.inject(
        SecretItem::DatabaseEncryptionKey,
        Call::Read,
        Injected::Malformed(16),
    );
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::Credential(_))),
        "a malformed key entry must fail closed, got {result:?}"
    );

    // --- path substitution -----------------------------------------------
    let fixture = Fixture::new();
    let paths = fixture.paths();
    paths.prepare().expect("prepare");
    std::fs::create_dir(paths.database()).expect("decoy directory");
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::StorePathRejected(_))),
        "a non-regular file at a store path must be rejected, got {result:?}"
    );
}

#[test]
fn missing_signing_entries_fail_their_operations_without_mutating_the_store() {
    // ADR-0007 §2: account and device signing entries follow registration and
    // enrollment, not store creation. Their absence must not fail store open,
    // and must never be answered by generating a replacement.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open with no signing seeds");
    assert!(!fixture.credentials.contains(SecretItem::DeviceSigningSeed));
    assert!(!fixture
        .credentials
        .contains(SecretItem::AccountIdentitySigningSeed));

    let missing = fixture
        .credentials
        .read(SecretItem::DeviceSigningSeed)
        .expect("absent is not an error");
    assert!(missing.is_none(), "no replacement seed is ever generated");
    assert!(!fixture.credentials.contains(SecretItem::DeviceSigningSeed));
    assert_eq!(
        store.conversations().expect("read").len(),
        0,
        "nothing was mutated by the failed lookup"
    );
    store.close().expect("close");
}

#[test]
fn the_startup_state_table_is_exhaustive() {
    // Guards against a future edit adding a branch to `open_or_create` without
    // adding it to the table ADR-0007 §2 publishes.
    let mut seen = std::collections::HashSet::new();
    for final_present in [false, true] {
        for staging in [false, true] {
            for key in [false, true] {
                seen.insert(format!(
                    "{:?}",
                    StartupState::classify(final_present, staging, key)
                ));
            }
        }
    }
    assert_eq!(
        seen.len(),
        7,
        "ADR-0007 §2's table has exactly 7 outcomes, found {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// store_release_uses_only_pinned_sqlcipher  (single-target half)
// ---------------------------------------------------------------------------

#[test]
fn store_release_uses_only_pinned_sqlcipher() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let paths = store.paths().clone();
    let key = store
        .database_encryption_key_for_evidence()
        .expect("evidence key");
    store.close().expect("close");

    let key = super::key::DatabaseEncryptionKey::from_bytes(key);
    let connection =
        open_hardened(&paths.database(), &key, OpenIntent::Existing).expect("reopen hardened");

    // Amendment 1 §A.7: read the pinned values back from the BUILT artifact.
    let version: String = connection
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .expect("cipher_version");
    assert_eq!(version.trim(), EXPECTED_CIPHER_VERSION);
    assert_eq!(version.trim(), "4.5.7 community");

    // Amendment 1 §A.1: OpenSSL is SQLCipher's COMPILED DEFAULT here, not a flag
    // the build script passes, so it is proved by readback and never assumed.
    let provider: String = connection
        .pragma_query_value(None, "cipher_provider", |row| row.get(0))
        .expect("cipher_provider");
    assert_eq!(provider.trim(), EXPECTED_CIPHER_PROVIDER);

    // Amendment 1 §A.6: `cipher_status` is SQLCipher 4.12.0+ and must be ABSENT
    // from the staged bundle. If it ever appears, the bundle changed under us
    // and §3's respecified open sequence needs revisiting.
    let status: Result<String, _> =
        connection.pragma_query_value(None, "cipher_status", |row| row.get(0));
    assert!(
        status.is_err(),
        "PRAGMA cipher_status must not exist on 4.5.7; got {status:?}"
    );

    // The Amendment 1 §A.5 flag table, as observable at runtime.
    let compile_options: Vec<String> = {
        let mut statement = connection
            .prepare("PRAGMA compile_options")
            .expect("compile_options");
        let options = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        options
    };
    let has = |needle: &str| compile_options.iter().any(|option| option == needle);

    assert!(has("HAS_CODEC"), "SQLITE_HAS_CODEC: {compile_options:?}");
    assert!(has("THREADSAFE=1"), "SQLITE_THREADSAFE=1");
    assert!(
        has("TEMP_STORE=2"),
        "Amendment 1 §A.5 accepts TEMP_STORE at 2, with §3's per-connection pin \
         delivering the guarantee: {compile_options:?}"
    );
    let temp_store: i64 = connection
        .pragma_query_value(None, "temp_store", |row| row.get(0))
        .expect("temp_store");
    assert_eq!(temp_store, 2, "the per-connection temp_store = MEMORY pin");

    // A.5 records these as compiled in and UNREACHABLE, not absent. The
    // assertion is deliberately that they ARE present: A.4's CVE foreclosure
    // rests on "compiled but unreachable", so if a future bundle actually
    // removed them the record must be corrected rather than quietly improved.
    assert!(has("ENABLE_FTS5"), "FTS5 is compiled in (build.rs:129)");
    assert!(
        has("ENABLE_FTS3") || has("ENABLE_FTS3_PARENTHESIS"),
        "docs/issues/011 N2: FTS3 is compiled in too (build.rs:127-128): {compile_options:?}"
    );
    // ...and the other half of the foreclosure: no FTS table is instantiated.
    let fts_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
              WHERE sql LIKE '%USING fts%' OR sql LIKE '%using fts%'",
            [],
            |row| row.get(0),
        )
        .expect("schema scan");
    assert_eq!(fts_tables, 0, "the schema creates no FTS table of any kind");

    // docs/issues/011 N1: the BEHAVIORAL probe, not an inspection.
    assert!(
        has("ENABLE_LOAD_EXTENSION"),
        "extension loading is compiled in (build.rs:131), so the pin has to be \
         a runtime one: {compile_options:?}"
    );
    probe_extension_loading_is_refused(&connection)
        .expect("load_extension() must be refused with \"not authorized\"");

    // And the probe is not vacuous about WHICH error it accepts: the refusal
    // must be SQLite's authorization refusal, not a loader error, because a
    // loader error would mean the flag was set and the call got through.
    let direct: Result<Option<String>, _> = connection.query_row(
        "SELECT load_extension('citadel-store-extension-loading-probe')",
        [],
        |row| row.get(0),
    );
    let message = match direct {
        Err(rusqlite::Error::SqliteFailure(_, Some(message))) => message,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(
        message.contains("not authorized"),
        "the exact refusal from sqlcipher/sqlite3.c:135071, got {message:?}"
    );

    // The remaining §3 settings, read back.
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal_mode");
    assert!(journal.eq_ignore_ascii_case("delete"), "{journal}");
    for (pragma, expected) in [
        ("synchronous", 2),
        ("secure_delete", 1),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
    ] {
        let actual: i64 = connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .unwrap_or_else(|error| panic!("{pragma}: {error}"));
        assert_eq!(actual, expected, "{pragma}");
    }
    // Returned as TEXT by SQLCipher, so it gets its own reader.
    assert_eq!(
        super::open::read_cipher_memory_security(&connection).expect("cipher_memory_security"),
        1
    );
    assert!(connection
        .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .expect("defensive"));
    assert!(!connection
        .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
        .expect("trusted schema"));
}

#[test]
fn a_wrong_key_fails_the_codec_proof_rather_than_resetting() {
    // Amendment 1 §A.6 step 3: encrypted schema access is the load-bearing,
    // version-independent codec proof. A connection whose codec is not active,
    // or is keyed wrongly, cannot read the schema at all.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let paths = store.paths().clone();
    store.close().expect("close");

    let wrong = super::key::DatabaseEncryptionKey::from_bytes(zeroize::Zeroizing::new([0x11; 32]));
    let result = open_hardened(&paths.database(), &wrong, OpenIntent::Existing);
    assert!(
        matches!(result, Err(StoreError::StoreUnreadable(_))),
        "a wrong key must fail the codec proof, got {result:?}"
    );
    assert!(
        paths.database().exists(),
        "and it must never trigger an empty-store reset"
    );
}

// ---------------------------------------------------------------------------
// store_rejects_plaintext_wrong_key_corruption_and_unverified_cipher
// ---------------------------------------------------------------------------

#[test]
fn store_rejects_plaintext_wrong_key_corruption_and_unverified_cipher() {
    // A plaintext SQLite database at the store path is refused, never converted.
    let fixture = Fixture::new();
    let paths = fixture.paths();
    paths.prepare().expect("prepare");
    {
        let plain = rusqlite::Connection::open(paths.database()).expect("plaintext db");
        plain
            .execute_batch("CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (1);")
            .expect("write plaintext");
    }
    let before = std::fs::read(paths.database()).expect("read");
    assert_eq!(
        &before[..16],
        b"SQLite format 3\0",
        "a real plaintext header"
    );
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::PlaintextDatabaseRejected)),
        "a plaintext database must be refused, got {result:?}"
    );
    // ...and left exactly as it was. Import is M8 work behind its own design.
    assert_eq!(std::fs::read(paths.database()).expect("read"), before);

    // A tampered page fails rather than opening or resetting.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let paths = store.paths().clone();
    let key = store.database_encryption_key_for_evidence().expect("key");
    store.close().expect("close");

    let mut bytes = std::fs::read(paths.database()).expect("read");
    let length = bytes.len();
    // Past the 16-byte SQLCipher salt, inside the first encrypted page.
    for byte in bytes.iter_mut().skip(200).take(64) {
        *byte ^= 0xFF;
    }
    assert_eq!(bytes.len(), length, "tampering must not change the length");
    std::fs::write(paths.database(), &bytes).expect("write tampered");

    let key = super::key::DatabaseEncryptionKey::from_bytes(key);
    let result = open_hardened(&paths.database(), &key, OpenIntent::Existing);
    assert!(
        result.is_err(),
        "a tampered page must not open, got {result:?}"
    );
    assert!(
        paths.database().exists(),
        "a failed open never resets the store to empty"
    );
}

// ---------------------------------------------------------------------------
// store_disk_copy_without_key_contains_no_canary_plaintext
// ---------------------------------------------------------------------------

#[test]
fn store_disk_copy_without_key_contains_no_canary_plaintext() {
    const CANARY: &[u8] = b"CITADEL-CANARY-a3f1c0de-plaintext-must-not-appear";
    const TITLE_CANARY: &[u8] = b"CITADEL-CANARY-conversation-title";

    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();
    store
        .create_group(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            Some(String::from_utf8(TITLE_CANARY.to_vec()).expect("utf-8")),
        )
        .expect("create");
    store
        .send(
            OperationId::generate().expect("id"),
            identity,
            group_id,
            CANARY.to_vec(),
        )
        .expect("send");
    let paths = store.paths().clone();
    store.close().expect("close");

    // Every file, not only the database: a sidecar carrying plaintext would be
    // exactly the leak this test exists to catch.
    let mut scanned = 0usize;
    for path in paths.all_files() {
        if path == paths.lock() || !path.exists() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        scanned += 1;
        assert!(
            !contains(&bytes, CANARY),
            "{path:?} contains the message canary in cleartext"
        );
        assert!(
            !contains(&bytes, TITLE_CANARY),
            "{path:?} contains the conversation title in cleartext"
        );
        // An unkeyed reader gets no schema either.
        assert!(
            !contains(&bytes, b"citadel_messages"),
            "{path:?} leaks the schema"
        );
    }
    assert!(scanned >= 1, "the scan must actually have read a file");

    // Non-vacuous control: the scanner finds a canary when one is really there.
    let mut planted = std::fs::read(paths.database()).expect("read");
    planted.extend_from_slice(CANARY);
    assert!(
        contains(&planted, CANARY),
        "the scanner must be able to find a canary it is given"
    );

    // Standard SQLite cannot read it, and a random SQLCipher key cannot either.
    let plain = rusqlite::Connection::open(paths.database()).expect("handle opens lazily");
    assert!(
        plain
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
            .is_err(),
        "standard SQLite must not read an encrypted database"
    );
    let random = super::key::DatabaseEncryptionKey::generate().expect("csprng");
    assert!(
        open_hardened(&paths.database(), &random, OpenIntent::Existing).is_err(),
        "a random SQLCipher key must not open it"
    );
}

// ---------------------------------------------------------------------------
// store_provider_and_application_share_one_transaction
// ---------------------------------------------------------------------------

#[test]
fn store_provider_and_application_share_one_transaction() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();

    let operation = OperationId::generate().expect("id");
    let created = store
        .create_group(operation, identity.clone(), group_id, None)
        .expect("create");
    assert_eq!(created, OperationOutcome::GroupCreated { epoch: 0 });

    // Both schemas moved in one transaction: the application conversation row
    // AND OpenMLS's own persisted group state.
    assert_eq!(store.conversations().expect("read").len(), 1);
    assert_eq!(store.group_epoch(group_id).expect("epoch"), 0);

    // Replaying the same operation ID returns the committed result and does not
    // mutate; a second conversation row would violate the primary key.
    let replay = store
        .create_group(operation, identity.clone(), group_id, None)
        .expect("replay returns the retained outcome");
    assert_eq!(replay, created);
    assert_eq!(store.conversations().expect("read").len(), 1);

    // The same ID with changed request fields is refused without mutation.
    let conflict = store.create_group(operation, identity.clone(), group_id, Some("x".into()));
    assert!(
        matches!(conflict, Err(StoreError::OperationIdConflict)),
        "{conflict:?}"
    );

    // A failing operation rolls BOTH schemas back.
    let missing = GroupId::new();
    let failure = store.send(
        OperationId::generate().expect("id"),
        identity.clone(),
        missing,
        b"never".to_vec(),
    );
    assert!(
        matches!(failure, Err(StoreError::UnknownGroup)),
        "{failure:?}"
    );
    assert_eq!(
        store.conversations().expect("read").len(),
        1,
        "the failed operation left no application row"
    );
    assert_eq!(
        store.messages(missing).expect("messages").len(),
        0,
        "and no message row"
    );

    // The high-water sequence advances and never decreases.
    let before = store.operation_high_water().expect("high water");
    store
        .send(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            b"one".to_vec(),
        )
        .expect("send");
    let after = store.operation_high_water().expect("high water");
    assert!(after > before, "{before} -> {after}");
    store.close().expect("close");
}

#[test]
fn the_outcome_ring_expires_payloads_without_ever_reapplying_the_operation() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();
    store
        .create_group(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            None,
        )
        .expect("create");

    // The operation whose outcome will be pushed out of the ring.
    let victim = OperationId::generate().expect("id");
    let first = store
        .send(victim, identity.clone(), group_id, b"first".to_vec())
        .expect("send");
    assert!(matches!(first, OperationOutcome::Sent { ref ciphertext } if !ciphertext.is_empty()));

    // Fill and wrap the ring.
    for index in 0..(RETAINED_OUTCOMES + 2) {
        store
            .send(
                OperationId::generate().expect("id"),
                identity.clone(),
                group_id,
                format!("filler-{index}").into_bytes(),
            )
            .expect("send");
    }

    // The ledger ROW survives, so the ID is still recognised — and it expires
    // rather than being applied a second time.
    let replay = store.send(victim, identity.clone(), group_id, b"first".to_vec());
    assert!(
        matches!(replay, Err(StoreError::OperationReceiptExpired)),
        "an expired receipt must never be reapplied, got {replay:?}"
    );

    // A recent operation's outcome is still returned exactly.
    let recent = OperationId::generate().expect("id");
    let sent = store
        .send(recent, identity.clone(), group_id, b"recent".to_vec())
        .expect("send");
    let replayed = store
        .send(recent, identity.clone(), group_id, b"recent".to_vec())
        .expect("replay");
    assert_eq!(sent, replayed, "a retained outcome returns byte for byte");

    // The high-water sequence never decreased across all of that pruning.
    let high_water = store.operation_high_water().expect("high water");
    assert!(high_water >= RETAINED_OUTCOMES + 3, "{high_water}");
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// store_codec_v1_roundtrips_golden_corpus_and_migrates
// ---------------------------------------------------------------------------

#[test]
fn store_codec_v1_roundtrips_golden_corpus_and_migrates() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();
    store
        .create_group(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            None,
        )
        .expect("create");
    store
        .send(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            b"corpus".to_vec(),
        )
        .expect("send");
    // A KeyPackage as well, so the corpus covers the one-time-pool entities and
    // their private keys rather than group data alone.
    store.new_key_package(identity).expect("key package");
    let paths = store.paths().clone();
    let key = store.database_encryption_key_for_evidence().expect("key");
    store.close().expect("close");

    let key_owned = super::key::DatabaseEncryptionKey::from_bytes(key);
    let connection =
        open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");

    // The identifier and version tuple were written BEFORE the first OpenMLS
    // record, so they are readable and exact.
    assert_eq!(
        read_metadata(&connection, meta_key::CODEC_ID).expect("meta"),
        Some(CODEC_ID.to_string())
    );
    assert_eq!(
        read_metadata(&connection, meta_key::CODEC_BOUND_VERSIONS).expect("meta"),
        Some(CODEC_BOUND_VERSIONS.to_string())
    );
    assert_eq!(
        read_metadata(&connection, meta_key::SCHEMA_SENTINEL).expect("meta"),
        Some(SCHEMA_SENTINEL.to_string())
    );

    // Every OpenMLS value the group produced decodes with v1, and re-encoding it
    // reproduces the stored bytes exactly. That is the round-trip property the
    // corpus pins: not "it parses", but "it writes back the same bytes".
    let rows: Vec<(String, Vec<u8>)> = {
        let mut statement = connection
            .prepare("SELECT data_type, group_data FROM openmls_group_data")
            .expect("provider rows");
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        rows
    };
    assert!(
        rows.len() >= 5,
        "a created group must have written several provider rows, got {}",
        rows.len()
    );
    for (data_type, bytes) in &rows {
        let value: serde_json::Value = CitadelOpenMlsJsonCodecV1::from_slice(bytes)
            .unwrap_or_else(|error| panic!("{data_type} did not decode with v1: {error}"));
        let reencoded = CitadelOpenMlsJsonCodecV1::to_vec(&value).expect("re-encode");
        assert_eq!(
            &reencoded, bytes,
            "{data_type} did not round-trip byte for byte"
        );
    }

    // The join config the provider persisted really does carry the zero pin, so
    // `DmGroup::load`'s fail-closed check reads a real field rather than a
    // constant this crate supplies.
    let (_, join_config_bytes) = rows
        .iter()
        .find(|(data_type, _)| data_type == "join_group_config")
        .expect("the join config is persisted");
    let join_config: serde_json::Value =
        CitadelOpenMlsJsonCodecV1::from_slice(join_config_bytes).expect("decode");
    assert_eq!(
        join_config.get("max_past_epochs").and_then(|v| v.as_u64()),
        Some(0),
        "ADR-0007 §6's pin must be visible in the PERSISTED configuration"
    );

    // Secret entities are covered too, not only group data. The HPKE private
    // keys are here; the SIGNATURE key pair deliberately is NOT, because
    // ADR-0007 §4 keeps the device and account signing seeds in their own OS
    // credential-store entries and out of the database entirely.
    let mut secret_counts = Vec::new();
    for table in [
        "openmls_encryption_keys",
        "openmls_epoch_keys_pairs",
        "openmls_key_packages",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("{table}: {error}"));
        secret_counts.push((table, count));
    }
    assert!(
        secret_counts.iter().any(|(_, count)| *count >= 1),
        "the corpus must include secret entities, not only group data: {secret_counts:?}"
    );
    let signature_keys: i64 = connection
        .query_row("SELECT count(*) FROM openmls_signature_keys", [], |row| {
            row.get(0)
        })
        .expect("signature keys");
    assert_eq!(
        signature_keys, 0,
        "the signing seed lives in the OS credential store; a copy in the          database would be a second place to compromise"
    );
    drop(connection);

    // An unknown codec identifier fails closed. There is no trial decoding.
    {
        let connection =
            open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
        connection
            .execute(
                "UPDATE citadel_store_meta SET value = 'citadel-openmls-json-v2' WHERE key = ?1",
                [meta_key::CODEC_ID],
            )
            .expect("rewrite identifier");
    }
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::UnsupportedCodec { .. })),
        "an unknown codec identifier must fail closed, got {result:?}"
    );

    // A changed bound-version tuple fails closed too, even though the bytes
    // would still decode: the identifier names a schema, not just an encoding.
    {
        let connection =
            open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
        connection
            .execute(
                "UPDATE citadel_store_meta SET value = ?2 WHERE key = ?1",
                rusqlite::params![meta_key::CODEC_ID, CODEC_ID],
            )
            .expect("restore identifier");
        connection
            .execute(
                "UPDATE citadel_store_meta SET value = 'openmls=0.9.0' WHERE key = ?1",
                [meta_key::CODEC_BOUND_VERSIONS],
            )
            .expect("rewrite tuple");
    }
    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::UnsupportedCodec { .. })),
        "a changed bound-version tuple must fail closed, got {result:?}"
    );
}

#[test]
fn store_migrations_are_encrypted_transactional_and_monotonic() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("fresh path");
    let paths = store.paths().clone();
    let key = store.database_encryption_key_for_evidence().expect("key");
    store.close().expect("close");

    let key_owned = super::key::DatabaseEncryptionKey::from_bytes(key);
    let connection =
        open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");

    // Two separate, NAMED migration histories in one encrypted database.
    let app: i64 = connection
        .query_row("SELECT MAX(version) FROM citadel_app_migrations", [], |r| {
            r.get(0)
        })
        .expect("app history");
    assert_eq!(app, APP_SCHEMA_VERSION);
    let provider: i64 = connection
        .query_row(
            "SELECT count(*) FROM openmls_sqlite_storage_migrations",
            [],
            |r| r.get(0),
        )
        .expect("provider history");
    assert!(provider >= 1, "the provider ran its own migrations");

    // No plaintext temporary database was left beside the store.
    for entry in std::fs::read_dir(paths.root()).expect("read dir") {
        let path = entry.expect("entry").path();
        let bytes = std::fs::read(&path).unwrap_or_default();
        if bytes.len() >= 16 {
            assert_ne!(
                &bytes[..16],
                b"SQLite format 3\0",
                "{path:?} is an unencrypted SQLite file beside the store"
            );
        }
    }

    // A newer schema version fails closed rather than being downgraded.
    connection
        .execute(
            "INSERT INTO citadel_app_migrations (version, applied_at) VALUES (?1, 0)",
            [APP_SCHEMA_VERSION + 1],
        )
        .expect("simulate a newer build's migration");
    connection
        .execute(
            "UPDATE citadel_store_meta SET value = ?2 WHERE key = ?1",
            rusqlite::params![meta_key::APP_SCHEMA_VERSION, APP_SCHEMA_VERSION + 1],
        )
        .expect("bump recorded version");
    drop(connection);

    let result = fixture.open();
    assert!(
        matches!(result, Err(StoreError::UnsupportedSchema { .. })),
        "a newer schema must fail closed, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// restart, pending transmissions, KT checkpoint
// ---------------------------------------------------------------------------

#[test]
fn store_restart_restores_group_and_pending_transmission_exactly_once() {
    let fixture = Fixture::new();
    let identity = local_identity();
    let group_id = GroupId::new();

    let operation = OperationId::generate().expect("id");
    let (ciphertext, epoch) = {
        let store = fixture.open().expect("open");
        store
            .create_group(
                OperationId::generate().expect("id"),
                identity.clone(),
                group_id,
                None,
            )
            .expect("create");
        let sent = store
            .send(operation, identity.clone(), group_id, b"payload".to_vec())
            .expect("send");
        let OperationOutcome::Sent { ciphertext } = sent else {
            panic!("{sent:?}");
        };
        let epoch = store.group_epoch(group_id).expect("epoch");
        // Simulates the client dying after commit but before the transport
        // acknowledged: the store closes with the pending row still there.
        store.close().expect("close");
        (ciphertext, epoch)
    };

    let store = fixture.open().expect("reopen");
    assert_eq!(
        store.group_epoch(group_id).expect("epoch"),
        epoch,
        "the group survived the restart"
    );

    let pending = store.pending_transmissions().expect("pending");
    let application: Vec<_> = pending.iter().filter(|p| p.kind == "application").collect();
    assert_eq!(application.len(), 1, "{pending:?}");
    assert_eq!(
        application[0].wire_bytes, ciphertext,
        "the EXACT bytes are retried, not regenerated"
    );
    assert_eq!(
        &application[0].idempotency_key,
        operation.as_bytes(),
        "the idempotency key is the caller's operation id"
    );
    let key = application[0].idempotency_key;

    // Retrying the same operation ID after restart returns the committed result
    // without advancing the ratchet a second time.
    let replay = store
        .send(operation, identity.clone(), group_id, b"payload".to_vec())
        .expect("replay");
    assert_eq!(replay, OperationOutcome::Sent { ciphertext });
    assert_eq!(
        store.messages(group_id).expect("messages").len(),
        1,
        "no second plaintext row"
    );

    store.acknowledge_transmission(key).expect("ack");
    assert!(store
        .pending_transmissions()
        .expect("pending")
        .iter()
        .all(|p| p.kind != "application"));
    store.close().expect("close");
}

#[test]
fn store_restart_preserves_kt_anti_rollback_checkpoint() {
    let fixture = Fixture::new();
    {
        let store = fixture.open().expect("open");
        store
            .accept_kt_head(OperationId::generate().expect("id"), 100, vec![0xAA; 32])
            .expect("accept");
        store
            .accept_kt_head(OperationId::generate().expect("id"), 250, vec![0xBB; 32])
            .expect("accept a larger consistent head");
        store.close().expect("close");
    }

    let store = fixture.open().expect("reopen");
    let checkpoint = store.kt_checkpoint().expect("read").expect("present");
    assert_eq!(checkpoint.tree_size, 250);
    assert_eq!(checkpoint.root_hash, vec![0xBB; 32]);

    // A shorter head is refused and does not move the checkpoint.
    let shorter = store.accept_kt_head(OperationId::generate().expect("id"), 100, vec![0xAA; 32]);
    assert!(shorter.is_err(), "{shorter:?}");
    // A forked head at the same size is refused too.
    let forked = store.accept_kt_head(OperationId::generate().expect("id"), 250, vec![0xCC; 32]);
    assert!(forked.is_err(), "{forked:?}");

    let after = store.kt_checkpoint().expect("read").expect("present");
    assert_eq!(after.tree_size, 250);
    assert_eq!(after.root_hash, vec![0xBB; 32]);
    store.close().expect("close");
}

#[test]
fn store_clean_open_does_not_run_a_full_integrity_scan() {
    // ADR-0007 §3 runs `cipher_integrity_check` at first creation, around
    // migrations, after unclean-shutdown recovery, and on explicit maintenance —
    // not on every clean open. The observable precondition is the rollback
    // journal: without one, the open takes the fast path.
    let fixture = Fixture::new();
    let store = fixture.open().expect("create");
    let paths = store.paths().clone();
    store.close().expect("close");

    assert!(
        !paths.journal().exists(),
        "a clean close leaves no rollback journal, which is what makes the fast \
         path safe to take"
    );
    let store = fixture.open().expect("clean reopen");
    // Explicit maintenance still works, and still passes.
    store.verify_integrity().expect("explicit maintenance scan");
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// store_profile_destruction_revokes_keys_and_reports_residual_files
// ---------------------------------------------------------------------------

#[test]
fn store_profile_destruction_revokes_keys_and_reports_residual_files() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();
    store
        .create_group(
            OperationId::generate().expect("id"),
            identity.clone(),
            group_id,
            None,
        )
        .expect("create");
    // Seed the other two credential entries so destruction has all three.
    fixture
        .credentials
        .seed(SecretItem::DeviceSigningSeed, [0x01; 32]);
    fixture
        .credentials
        .seed(SecretItem::AccountIdentitySigningSeed, [0x02; 32]);

    let paths = store.paths().clone();
    let report = store.destroy().expect("destroy");
    assert!(
        report.is_complete(),
        "destruction must confirm every credential and file absent: {report:?}"
    );
    for item in SecretItem::ALL {
        assert!(!fixture.credentials.contains(item), "{item:?} survived");
    }
    assert!(!paths.database().exists());
    assert!(!paths.staging().exists());
    for sidecar in paths.sidecars() {
        assert!(!sidecar.exists(), "{sidecar:?} survived");
    }

    // Partial failure is REPORTED, not swallowed, and every deletion is still
    // attempted rather than stopping at the first error.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    fixture
        .credentials
        .seed(SecretItem::DeviceSigningSeed, [0x03; 32]);
    fixture.credentials.inject(
        SecretItem::DatabaseEncryptionKey,
        Call::Delete,
        Injected::Locked,
    );
    let report = store.destroy().expect("destroy runs to completion");
    assert!(!report.is_complete());
    assert_eq!(report.credential_failures.len(), 1, "{report:?}");
    assert!(
        !fixture.credentials.contains(SecretItem::DeviceSigningSeed),
        "the other credentials were still attempted, and deleted"
    );
    assert!(report.residual_paths.is_empty(), "{report:?}");
}

// ---------------------------------------------------------------------------
// two-peer fixture, receive atomicity, and forward secrecy
// ---------------------------------------------------------------------------

/// A two-peer fixture: `remote` is an in-memory peer, the store is the persisted
/// one under test. The remote's ephemeral provider is deliberate — it models a
/// correspondent whose state this test does not control.
struct Pair {
    remote_provider: EphemeralProvider,
    remote_identity: DeviceIdentity,
    remote_group: DmGroup,
    verifier: Arc<AllowList>,
    group_id: GroupId,
}

fn pair(store: &LocalStore, local: Arc<DeviceIdentity>) -> Pair {
    let remote = make_identity();
    let remote_provider = EphemeralProvider::default();

    // The local peer's KeyPackage must be generated INSIDE the store, or its
    // private init and encryption keys would not be persisted and the join
    // could not survive a restart.
    let key_package = store
        .new_key_package(local.clone())
        .expect("store-backed key package");

    let verifier = Arc::new(AllowList(vec![
        (remote.account_id, remote.identity_pubkey.0),
        (
            local.device_credential.tbs.account_id,
            local.device_credential.tbs.identity_pubkey.0,
        ),
    ]));

    let group_id = GroupId::new();
    let mut remote_group = DmGroup::create(&remote_provider, &remote.identity, group_id)
        .expect("remote creates the group");
    let output = remote_group
        .add_members(
            &remote_provider,
            &remote.identity,
            &[key_package],
            verifier.as_ref(),
        )
        .expect("remote adds the local peer");

    store
        .join_from_welcome(
            OperationId::generate().expect("id"),
            group_id,
            output.welcome_bytes,
            verifier.clone(),
            None,
        )
        .expect("local peer joins into the store");

    Pair {
        remote_provider,
        remote_identity: remote.identity,
        remote_group,
        verifier,
        group_id,
    }
}

#[test]
fn store_receive_is_atomic_with_plaintext_and_mls_state() {
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let mut peer = pair(&store, identity.clone());

    let ciphertext = peer
        .remote_group
        .send(&peer.remote_provider, &peer.remote_identity, b"hello")
        .expect("remote sends");

    let received = store
        .receive(
            OperationId::generate().expect("id"),
            peer.group_id,
            ciphertext.clone(),
            peer.verifier.clone(),
        )
        .expect("receive");
    assert_eq!(
        received,
        OperationOutcome::ReceivedApplication {
            plaintext: b"hello".to_vec(),
            deduplicated: false
        }
    );
    assert_eq!(store.messages(peer.group_id).expect("messages").len(), 1);

    // A replayed delivery under a DIFFERENT operation id is deduplicated before
    // any MLS work, so no ratchet advances and no second plaintext row lands.
    let replay = store
        .receive(
            OperationId::generate().expect("id"),
            peer.group_id,
            ciphertext.clone(),
            peer.verifier.clone(),
        )
        .expect("dedup");
    assert_eq!(
        replay,
        OperationOutcome::ReceivedApplication {
            plaintext: b"hello".to_vec(),
            deduplicated: true
        }
    );
    assert_eq!(store.messages(peer.group_id).expect("messages").len(), 1);

    // A corrupted message lands neither the row nor the receiver state.
    let mut corrupted = ciphertext.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    let failure = store.receive(
        OperationId::generate().expect("id"),
        peer.group_id,
        corrupted,
        peer.verifier.clone(),
    );
    assert!(failure.is_err(), "{failure:?}");
    assert_eq!(
        store.messages(peer.group_id).expect("messages").len(),
        1,
        "the failed receive left no plaintext row"
    );

    // The next legitimate message still decrypts, proving the failed receive did
    // not half-advance the receiver.
    let next = peer
        .remote_group
        .send(&peer.remote_provider, &peer.remote_identity, b"second")
        .expect("remote sends again");
    let outcome = store
        .receive(
            OperationId::generate().expect("id"),
            peer.group_id,
            next,
            peer.verifier.clone(),
        )
        .expect("receive");
    assert!(matches!(
        outcome,
        OperationOutcome::ReceivedApplication { ref plaintext, .. } if plaintext == b"second"
    ));
    store.close().expect("close");
}

#[test]
fn post_restart_snapshot_proves_mls_forward_secrecy() {
    let fixture = Fixture::new();
    let snapshots = tempfile::tempdir().expect("snapshot dir");
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let mut peer = pair(&store, identity.clone());

    // One message the local peer DOES process, so there is retained plaintext
    // history in the snapshot. Without it, the final assertion about what this
    // claim does not cover would be vacuously true.
    let delivered = peer
        .remote_group
        .send(
            &peer.remote_provider,
            &peer.remote_identity,
            b"retained-history",
        )
        .expect("remote sends a message the local peer receives");
    store
        .receive(
            OperationId::generate().expect("id"),
            peer.group_id,
            delivered,
            peer.verifier.clone(),
        )
        .expect("receive");

    // An old-epoch application ciphertext the local peer has NEVER processed.
    let old_ciphertext = peer
        .remote_group
        .send(
            &peer.remote_provider,
            &peer.remote_identity,
            b"old-epoch-secret",
        )
        .expect("remote sends at the old epoch");
    let old_epoch = store.group_epoch(peer.group_id).expect("epoch");
    store.close().expect("quiesce before snapshotting");

    // --- pre-transition control: this snapshot MUST decrypt it -----------
    let before = {
        let key = fixture
            .credentials
            .read(SecretItem::DatabaseEncryptionKey)
            .expect("read")
            .expect("present");
        CapturedSnapshot::capture_files(&fixture.paths(), key, &snapshots.path().join("before"))
            .expect("capture")
    };
    assert!(
        !before.has_live_rollback_journal(),
        "a quiescent snapshot has no live rollback journal"
    );
    assert!(
        before
            .copied_files()
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("citadel.db")),
        "the snapshot must include the database: {:?}",
        before.copied_files()
    );
    {
        let mut reopened = before.reopen().expect("reopen the pre-transition snapshot");
        assert_eq!(
            reopened.max_past_epochs(peer.group_id).expect("retention"),
            Some(0),
            "ADR-0007 §6's pin must hold across a restart"
        );
        let outcome = reopened
            .try_process_message(peer.group_id, protocol_message(&old_ciphertext))
            .expect("drive the real receive path")
            .expect("the PRE-transition control MUST decrypt; if it cannot, this test is invalid");
        match outcome.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let plaintext = crate::padding::unpad(&app.into_bytes()).expect("unpad");
                assert_eq!(plaintext, b"old-epoch-secret");
            }
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    // --- the epoch transition -------------------------------------------
    let store = fixture.open().expect("reopen");
    let prepared = store
        .prepare_self_update(
            OperationId::generate().expect("id"),
            identity.clone(),
            peer.group_id,
        )
        .expect("prepare");
    let OperationOutcome::SelfUpdatePrepared { commit_bytes, .. } = prepared else {
        panic!("{prepared:?}");
    };
    let confirmed = store
        .confirm_self_update(OperationId::generate().expect("id"), peer.group_id)
        .expect("confirm");
    let OperationOutcome::SelfUpdateConfirmed { epoch: new_epoch } = confirmed else {
        panic!("{confirmed:?}");
    };
    assert!(new_epoch > old_epoch, "{old_epoch} -> {new_epoch}");

    // The remote merges the same commit so it can produce a CURRENT-epoch
    // ciphertext for the positive control.
    let merged = peer
        .remote_group
        .receive(&peer.remote_provider, &commit_bytes, peer.verifier.as_ref())
        .expect("remote merges the self-update");
    assert_eq!(merged, ReceiveOutcome::CommitMerged { epoch: new_epoch });
    let current_ciphertext = peer
        .remote_group
        .send(
            &peer.remote_provider,
            &peer.remote_identity,
            b"current-epoch-message",
        )
        .expect("remote sends at the new epoch");

    // The transition returned success, so the live filesystem is quiescent and
    // the snapshot is taken with NO special cleanup (ADR-0007 §6).
    store.close().expect("close");
    let after = {
        let key = fixture
            .credentials
            .read(SecretItem::DatabaseEncryptionKey)
            .expect("read")
            .expect("present");
        CapturedSnapshot::capture_files(&fixture.paths(), key, &snapshots.path().join("after"))
            .expect("capture")
    };
    assert!(!after.has_live_rollback_journal());

    let mut reopened = after.reopen().expect("reopen with the CORRECT key");
    assert_eq!(
        reopened.group_epoch(peer.group_id).expect("epoch"),
        new_epoch
    );

    // Positive control FIRST: the attacker's snapshot is a working client.
    let control = reopened
        .try_process_message(peer.group_id, protocol_message(&current_ciphertext))
        .expect("drive")
        .expect("a never-processed CURRENT-epoch ciphertext must decrypt");
    match control.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(
                crate::padding::unpad(&app.into_bytes()).expect("unpad"),
                b"current-epoch-message"
            );
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // The claim: current persisted MLS secret state cannot decrypt a previously
    // unseen OLD-epoch ciphertext. Application deduplication is bypassed, so the
    // failure comes from OpenMLS's secret tree and not from application code.
    let error = reopened
        .try_process_message(peer.group_id, protocol_message(&old_ciphertext))
        .expect("drive")
        .expect_err("the old-epoch ciphertext must NOT decrypt");

    // The exact chain ADR-0007 §6 requires. A parser error, an application-level
    // epoch comparison, or a replay rejection is explicitly not sufficient.
    match error {
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
        )) => {}
        other => panic!(
            "expected ProcessMessageError::ValidationError -> UnableToDecrypt -> \
             SecretTreeError(TooDistantInThePast), got {other:?}"
        ),
    }

    // The boundary the ADR is equally explicit about, asserted rather than left
    // implied: retained plaintext history in the SAME snapshot is still readable
    // to this attacker. Forward secrecy is a property of key material, not of a
    // local plaintext archive, and a reader of this test must not infer more.
    let retained: i64 = reopened
        .connection()
        .query_row("SELECT count(*) FROM citadel_messages", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert!(
        retained >= 1,
        "the snapshot still contains readable local history, which is exactly \
         what ADR-0007 §6 says this claim does NOT cover"
    );
}

#[test]
fn store_epoch_transition_removes_obsolete_secret_bytes() {
    // The LOGICAL half of ADR-0007's evidence test, plus a raw-file byte scan.
    //
    // What is NOT here, stated plainly: the `SQLITE_ENABLE_DBPAGE_VTAB` plus
    // upstream `dbdata.c` recovery harness that reconstructs B-tree cells,
    // overflow chains, and recoverable deleted records. That needs a separate
    // evidence build of the pinned SQLCipher source and it has not been built.
    // Until it is, this test proves the obsolete secrets are gone from the
    // provider's logical rows and do not appear verbatim in the file — it does
    // NOT prove they are unrecoverable from freed pages.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let mut peer = pair(&store, identity.clone());

    // Exchange a message so message secrets exist at the old epoch.
    let ciphertext = peer
        .remote_group
        .send(&peer.remote_provider, &peer.remote_identity, b"pre")
        .expect("send");
    store
        .receive(
            OperationId::generate().expect("id"),
            peer.group_id,
            ciphertext,
            peer.verifier.clone(),
        )
        .expect("receive");

    let paths = store.paths().clone();
    let key = store.database_encryption_key_for_evidence().expect("key");
    store.close().expect("close");

    // Capture the exact pre-transition provider secret rows.
    let key_owned = super::key::DatabaseEncryptionKey::from_bytes(key);
    let captured: Vec<Vec<u8>> = {
        let connection =
            open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
        let mut statement = connection
            .prepare(
                "SELECT group_data FROM openmls_group_data WHERE data_type = 'message_secrets'",
            )
            .expect("prepare");
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        rows
    };
    assert!(
        !captured.is_empty(),
        "there must be message secrets to lose; otherwise this test is vacuous"
    );

    // Pre-transition positive control: the captured values ARE recoverable from
    // the decrypted database right now. Without this, a green result after the
    // transition would mean nothing.
    {
        let connection =
            open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
        for value in &captured {
            let found: i64 = connection
                .query_row(
                    "SELECT count(*) FROM openmls_group_data WHERE group_data = ?1",
                    [value],
                    |row| row.get(0),
                )
                .expect("control query");
            assert_eq!(found, 1, "the pre-transition control must find every value");
        }
    }

    // The transition.
    let store = fixture.open().expect("reopen");
    store
        .prepare_self_update(
            OperationId::generate().expect("id"),
            identity.clone(),
            peer.group_id,
        )
        .expect("prepare");
    store
        .confirm_self_update(OperationId::generate().expect("id"), peer.group_id)
        .expect("confirm");
    store.close().expect("close");

    {
        let connection =
            open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
        for value in &captured {
            let found: i64 = connection
                .query_row(
                    "SELECT count(*) FROM openmls_group_data WHERE group_data = ?1",
                    [value],
                    |row| row.get(0),
                )
                .expect("post query");
            assert_eq!(
                found, 0,
                "an obsolete secret row survived the epoch transition"
            );
        }
    }

    // The raw-file half: the obsolete bytes must not appear verbatim in the
    // encrypted file either. This is weaker than page reconstruction, and the
    // comment at the top of this test says so.
    let raw = std::fs::read(paths.database()).expect("read");
    for value in &captured {
        assert!(
            !contains(&raw, value),
            "an obsolete secret appears verbatim in the database file"
        );
    }
}

#[test]
fn a_group_whose_persisted_configuration_retains_past_epochs_fails_closed() {
    // Proves ADR-0007 §6's fail-closed check is wired to the PERSISTED
    // configuration, by rewriting that row to a widened config and showing the
    // load refuses. Without this, `PastEpochRetentionRejected` would be
    // unreachable code asserting a property nothing tests.
    let fixture = Fixture::new();
    let store = fixture.open().expect("open");
    let identity = local_identity();
    let group_id = GroupId::new();
    store
        .create_group(
            OperationId::generate().expect("id"),
            identity,
            group_id,
            None,
        )
        .expect("create");
    let paths = store.paths().clone();
    let key = store.database_encryption_key_for_evidence().expect("key");
    store.close().expect("close");

    let key_owned = super::key::DatabaseEncryptionKey::from_bytes(key);
    let mut connection =
        open_hardened(&paths.database(), &key_owned, OpenIntent::Existing).expect("reopen");
    let widened = MlsGroupJoinConfig::builder().max_past_epochs(3).build();
    let bytes = CitadelOpenMlsJsonCodecV1::to_vec(&widened).expect("encode");
    connection
        .execute(
            "UPDATE openmls_group_data SET group_data = ?1 WHERE data_type = 'join_group_config'",
            [&bytes],
        )
        .expect("widen the persisted configuration");

    let transaction = connection.transaction().expect("tx");
    let provider = StoreProvider::new(&transaction);
    let result = DmGroup::load(&provider, &group_id, None);
    assert!(
        matches!(result, Err(GroupError::PastEpochRetentionRejected(3))),
        "a widened persisted configuration must fail closed, got {result:?}"
    );
}
