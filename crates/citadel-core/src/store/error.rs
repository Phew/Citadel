//! Typed store errors.
//!
//! ADR-0007 §2 is explicit that every unavailable, locked, missing, duplicate,
//! malformed, or inaccessible state **fails closed**. No variant here is
//! recoverable by generating a replacement key, resetting to an empty store, or
//! converting a plaintext database in place; the variants exist so a caller can
//! tell those states apart and so recovery is always an explicit action.

use std::path::PathBuf;

/// Everything the local encrypted client store can refuse to do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    // ---- ADR-0007 §2: startup state machine ----
    /// The database exists but its database encryption key entry does not.
    /// Citadel never generates a replacement: a new key would make the existing
    /// ciphertext permanently unreadable while looking like a successful start.
    #[error("the database exists but its database encryption key entry is absent; no replacement key is ever generated")]
    StoreKeyMissing,

    /// A combination of paths and credential entries that no ordinary sequence
    /// produces. Requires an explicit reset or recovery action.
    #[error("store state is inconsistent and requires explicit recovery: {0}")]
    StoreStateInconsistent(&'static str),

    /// Another process holds the OS-enforced exclusive profile lock.
    #[error("another process already holds this profile: {0}")]
    StoreAlreadyOpen(PathBuf),

    /// A path escaped the fixed profile directory, or resolved through a
    /// symbolic link or Windows reparse point.
    #[error("refusing a store path outside the profile directory or reached through a link: {0}")]
    StorePathRejected(PathBuf),

    /// A standard SQLite header was found at the configured path. ADR-0007 §1:
    /// no plaintext database is ever accepted or converted in place.
    #[error("a plaintext SQLite database is at the store path; import is M8 work behind a separate design")]
    PlaintextDatabaseRejected,

    // ---- ADR-0007 §3: connection hardening ----
    /// A required pragma, db-config, or codec property could not be set or,
    /// having been set, did not read back with the required value. §3: failure
    /// to enable **or verify** a required setting aborts opening the store.
    #[error(
        "required store setting {setting} did not verify: expected {expected}, read back {actual}"
    )]
    HardeningNotVerified {
        /// The pragma, db-config, or probe that failed.
        setting: &'static str,
        /// What ADR-0007 §3 or Amendment 1 §A.5 requires.
        expected: String,
        /// What the built artifact actually reported.
        actual: String,
    },

    /// The database could not be opened with the supplied key, is corrupt, or
    /// is not in a supported SQLCipher format. Never an empty-store reset.
    #[error("the store did not open with the supplied database encryption key, or its pages failed authentication")]
    StoreUnreadable(#[source] rusqlite::Error),

    /// `cipher_integrity_check` reported at least one problem.
    #[error("cipher_integrity_check reported {0} problem(s)")]
    IntegrityCheckFailed(usize),

    // ---- ADR-0007 §5: transaction and crash contract ----
    /// A known operation ID arrived again with a different operation kind or a
    /// different canonical request fingerprint. No mutation is performed.
    #[error("operation id was already used for a different request")]
    OperationIdConflict,

    /// The ledger row survives, but its retained outcome was pruned out of the
    /// 256-entry ring. The request is never applied a second time.
    #[error("this operation already committed, but its outcome is no longer retained")]
    OperationReceiptExpired,

    /// The per-profile operation sequence cannot be incremented.
    #[error("the per-profile operation sequence is exhausted")]
    OperationSequenceExhausted,

    /// A commit failed with an indeterminate outcome and reconciliation could
    /// not read or validate the receipt. The caller must reconcile; the actor
    /// never blindly repeats an MLS mutation.
    #[error("commit outcome is indeterminate and requires reconciliation")]
    StoreOutcomeIndeterminate,

    /// The persisted group configuration retains past epochs. ADR-0007 §6 pins
    /// `max_past_epochs = 0` and fails closed if an upgrade widens it.
    #[error("persisted group configuration retains {0} past epoch(s); ADR-0007 §6 pins zero")]
    PastEpochRetentionRejected(usize),

    /// A group was addressed that this profile does not hold.
    #[error("no such group in this store")]
    UnknownGroup,

    // ---- ADR-0007 §1: codec and migrations ----
    /// The database declares a codec identifier or bound-version tuple this
    /// build does not implement. There is no trial decoding between codecs.
    #[error("unsupported storage codec: database says {found}, this build implements {expected}")]
    UnsupportedCodec {
        /// What the database's metadata declares.
        found: String,
        /// What this build can decode.
        expected: String,
    },

    /// The database is at a newer application schema version than this build.
    #[error("database application schema {found} is newer than this build's {supported}")]
    UnsupportedSchema {
        /// Version recorded in the database.
        found: i64,
        /// Highest version this build knows.
        supported: i64,
    },

    /// Encoding or decoding an OpenMLS storage value failed.
    #[error("storage codec: {0}")]
    Codec(#[from] crate::store::codec::CodecError),

    // ---- Credential store ----
    /// The OS credential store refused, or returned something unusable.
    #[error("credential store: {0}")]
    Credential(#[from] crate::store::credentials::CredentialStoreError),

    // ---- Plumbing ----
    /// The store actor thread is gone. Every in-flight call fails rather than
    /// silently degrading to an unserialized path.
    #[error("the store actor is not running")]
    ActorStopped,

    /// A group operation refused inside the transaction; the transaction rolled
    /// back and the loaded group object was discarded.
    #[error("group operation: {0}")]
    Group(#[from] crate::group::GroupError),

    /// Bridging the device identity into MLS failed.
    #[error("identity: {0}")]
    Identity(#[from] crate::identity::IdentityError),

    /// A filesystem operation on a profile path failed.
    #[error("store file {path}: {source}")]
    Io {
        /// The path being operated on.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// SQL that is not one of the classified conditions above.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A migration failed. Migrations are transactional and never reset user
    /// state, so the store is left exactly as it was.
    #[error("migration: {0}")]
    Migration(String),
}

impl StoreError {
    /// Attach a path to an I/O failure without repeating the map_err closure.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }

    /// A readback mismatch, formatted uniformly so evidence tests can match on
    /// the setting name rather than on prose.
    pub(crate) fn not_verified(
        setting: &'static str,
        expected: impl std::fmt::Display,
        actual: impl std::fmt::Display,
    ) -> Self {
        StoreError::HardeningNotVerified {
            setting,
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }
}
