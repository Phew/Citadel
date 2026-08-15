//! The local encrypted client store (ADR-0007, ACCEPTED 2026-07-26).
//!
//! This is where Citadel's MLS state stops being in-memory. Before it, a
//! process restart lost every group, and there was no durable state whose
//! deletion could support an honest forward-secrecy test. That is not a
//! side-benefit of this module — it is its reason for existing.
//!
//! # What it is
//!
//! - **SQLCipher whole-database encryption** over the stock bundled amalgamation
//!   in `libsqlite3-sys` 0.30.1 (SQLCipher 4.5.7 community, embedded SQLite
//!   3.45.3). M2 ships no source overlay; Amendment 1 §A staged the
//!   reproducibility program out to its own ADR.
//! - **A 32-byte database encryption key** that exists at rest only in the OS
//!   credential store, never derived from anything, never serialized anywhere
//!   else ([`credentials`], [`key`]).
//! - **OpenMLS's own published storage provider** behind a pinned deterministic
//!   codec ([`codec`], [`provider`]). Citadel does not hand-write the versioned
//!   storage trait that deletes MLS secrets.
//! - **One actor, one connection, one transaction per operation** ([`actor`]),
//!   so OpenMLS state and application state commit or roll back together.
//!
//! # What it does not claim
//!
//! ADR-0007 §6 draws the boundary and this module does not widen it:
//!
//! - Forward secrecy here means **current persisted MLS secret state cannot
//!   decrypt a previously unseen old-epoch ciphertext after obsolete epoch state
//!   is deleted**, proved against an attacker holding the database, every
//!   sidecar file, *and* the correct key. It does **not** make deliberately
//!   retained decrypted message history unreadable — those rows are readable to
//!   anyone with that key, and making them unreadable is a retention feature
//!   needing its own accepted design.
//! - None of the hardening defeats a live process compromise, OS paging,
//!   hibernation capture, or raw-device forensic recovery.
//! - SQLCipher page authentication detects modification, not freshness.
//!   Replacing the whole live file set with a valid older encrypted snapshot
//!   also rolls the KT checkpoint back, and M2 does not detect it.
//!
//! # Where the evidence lives
//!
//! [`crate::store::tests`] holds the named ADR-0007 evidence tests that can run
//! without release CI. The three that cannot — the three-desktop-target release
//! build, the native-backend conformance run per OS, and the PCS differential
//! oracle — are named in the PR that landed this module together with what
//! provisions them.

pub mod actor;
pub mod codec;
pub mod credentials;
pub mod error;
pub mod key;
pub mod ledger;
pub mod lifecycle;
pub mod lock;
pub mod open;
pub mod paths;
pub mod provider;
pub mod schema;

#[cfg(any(test, feature = "testing"))]
pub mod evidence;

#[cfg(test)]
mod tests;

pub use actor::{
    ConversationRow, KtCheckpoint, LocalStore, MessageRow, OperationOutcome, PendingTransmission,
};
pub use codec::{CitadelOpenMlsJsonCodecV1, CODEC_BOUND_VERSIONS, CODEC_ID};
pub use credentials::{CredentialStore, CredentialStoreError, NativeCredentialStore, SecretItem};
pub use error::StoreError;
pub use key::DatabaseEncryptionKey;
pub use ledger::{OperationId, OperationKind, RETAINED_OUTCOMES};
pub use lifecycle::{DestructionReport, StartupState};
pub use paths::ProfilePaths;
pub use provider::StoreProvider;
