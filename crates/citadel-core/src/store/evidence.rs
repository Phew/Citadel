//! Attacker-snapshot capture and reopen, for ADR-0007 §6's evidence tests.
//!
//! **Test configuration only** (`cfg(any(test, feature = "testing"))`), so none
//! of it is in a production dependency graph.
//!
//! ADR-0007 §6's forward-secrecy test gives the attacker a copy of the current
//! encrypted database, **every** SQLite sidecar file, and the **correct**
//! database encryption key, then requires that current persisted MLS secret
//! state cannot decrypt a previously unseen old-epoch ciphertext. That is a
//! deliberately strong attacker: merely deleting the key would prove key
//! separation, not forward secrecy, and ADR-0007 Alternative 9 rejects it by
//! name.
//!
//! Two rules this module exists to enforce, because a test that gets them wrong
//! passes while proving nothing:
//!
//! 1. **Copy without special cleanup.** [`CapturedSnapshot::capture`] copies the
//!    live files exactly as they are. It does not checkpoint, vacuum, or
//!    `secure_delete`-sweep first. ADR-0007 §6 is explicit that there is no
//!    test-only cleanup step.
//! 2. **Reopen through the real provider.** [`ReopenedSnapshot`] keys the copy
//!    with the same `open_hardened` sequence production uses and drives the real
//!    [`crate::group::DmGroup`] / [`StoreProvider`] path, so what the test
//!    observes is what the client would observe.
//!
//! A snapshot is eligible for the forward-secrecy assertion only when it was
//! taken from a **quiescent** store — after a state-changing operation returned
//! success, or after recovery confirmed the new epoch with no live rollback
//! journal. [`CapturedSnapshot::has_live_rollback_journal`] reports the second
//! condition so a test can assert it rather than assume it.

use super::error::StoreError;
use super::key::DatabaseEncryptionKey;
use super::open::{open_hardened, OpenIntent};
use super::paths::ProfilePaths;
use super::provider::StoreProvider;
use crate::group::DmGroup;
use crate::store::actor::LocalStore;
use citadel_proto::ids::GroupId as ProtoGroupId;
use openmls::prelude::{ProcessMessageError, ProcessedMessage, ProtocolMessage};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// A byte-for-byte copy of a store's files, plus the correct key.
pub struct CapturedSnapshot {
    paths: ProfilePaths,
    key: Zeroizing<[u8; 32]>,
    copied: Vec<PathBuf>,
}

impl CapturedSnapshot {
    /// Copy every file of a quiescent store into `into`, and take its key.
    ///
    /// The caller is responsible for quiescence. In practice that means the last
    /// state-changing call returned success, because a successful commit on a
    /// live filesystem has already removed the rollback journal.
    pub fn capture(store: &LocalStore, into: &Path) -> Result<Self, StoreError> {
        let key = store.database_encryption_key_for_evidence()?;
        Self::capture_files(store.paths(), key, into)
    }

    /// Copy the files of a store that is already closed, with a key the caller
    /// supplies. Used to snapshot a profile whose actor has been shut down.
    pub fn capture_files(
        source: &ProfilePaths,
        key: Zeroizing<[u8; 32]>,
        into: &Path,
    ) -> Result<Self, StoreError> {
        std::fs::create_dir_all(into).map_err(|error| StoreError::io(into, error))?;
        let destination = ProfilePaths::at_root(into);
        let mut copied = Vec::new();

        for path in source.all_files() {
            // The lock is not part of the attacker's material: it carries no
            // data and copying it would only confuse the reopened profile.
            if path == source.lock() {
                continue;
            }
            if !path.exists() {
                continue;
            }
            let name = path
                .file_name()
                .expect("every profile path has a file name")
                .to_owned();
            let target = into.join(&name);
            std::fs::copy(&path, &target).map_err(|error| StoreError::io(target.clone(), error))?;
            copied.push(target);
        }

        Ok(Self {
            paths: destination,
            key,
            copied,
        })
    }

    /// The snapshot's own profile paths.
    pub fn paths(&self) -> &ProfilePaths {
        &self.paths
    }

    /// Every file that was actually copied, so a test can assert the sidecar set
    /// it expected was present rather than silently snapshotting one file.
    pub fn copied_files(&self) -> &[PathBuf] {
        &self.copied
    }

    /// Whether the snapshot contains a rollback journal.
    ///
    /// A snapshot with one is **not** yet eligible for the forward-secrecy
    /// assertion: it is an indeterminate state that must be reopened and
    /// recovered first, and its durable epoch established.
    pub fn has_live_rollback_journal(&self) -> bool {
        self.paths.journal().exists()
    }

    /// Reopen the copy as an attacker who holds the correct key.
    ///
    /// Deliberately does **not** consult the OS credential store: the attacker
    /// model is files-plus-key, and reading the live credential store here would
    /// quietly make the test depend on the victim's machine still being intact.
    pub fn reopen(&self) -> Result<ReopenedSnapshot, StoreError> {
        let key = DatabaseEncryptionKey::from_bytes(self.key.clone());
        let connection = open_hardened(&self.paths.database(), &key, OpenIntent::Existing)?;
        super::schema::verify_store_identity(&connection)?;
        Ok(ReopenedSnapshot { connection })
    }

    /// Reopen with a key that is not the right one, for the negative control in
    /// `store_rejects_plaintext_wrong_key_corruption_and_unverified_cipher`.
    pub fn reopen_with_key(&self, key: [u8; 32]) -> Result<ReopenedSnapshot, StoreError> {
        let key = DatabaseEncryptionKey::from_bytes(Zeroizing::new(key));
        let connection = open_hardened(&self.paths.database(), &key, OpenIntent::Existing)?;
        Ok(ReopenedSnapshot { connection })
    }
}

/// A captured snapshot, reopened through the production open sequence.
pub struct ReopenedSnapshot {
    connection: Connection,
}

impl ReopenedSnapshot {
    /// The raw connection, for byte-level and schema-level inspection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The durable epoch of a group in the snapshot.
    pub fn group_epoch(&mut self, group_id: ProtoGroupId) -> Result<u64, StoreError> {
        let transaction = self.connection.transaction()?;
        let provider = StoreProvider::new(&transaction);
        let group = DmGroup::load(&provider, &group_id, None)?.ok_or(StoreError::UnknownGroup)?;
        let epoch = group.epoch();
        transaction.rollback()?;
        Ok(epoch)
    }

    /// How many past epochs the snapshot's persisted group configuration
    /// retains. ADR-0007 §6's evidence asserts this is zero rather than assuming
    /// the pin held across a restart.
    ///
    /// `None` means the field could not be read at all, which an openmls upgrade
    /// that renamed it would cause. A test must treat that as a failure, not as
    /// zero.
    pub fn max_past_epochs(&mut self, group_id: ProtoGroupId) -> Result<Option<usize>, StoreError> {
        let transaction = self.connection.transaction()?;
        let provider = StoreProvider::new(&transaction);
        let group = DmGroup::load(&provider, &group_id, None)?.ok_or(StoreError::UnknownGroup)?;
        let retained = group.max_past_epochs();
        transaction.rollback()?;
        Ok(retained)
    }

    /// Feed one MLS message to the snapshot's persisted group through the real
    /// OpenMLS path, **bypassing application deduplication**, and return
    /// OpenMLS's own typed result.
    ///
    /// Bypassing dedup is required, not a shortcut: ADR-0007 §6 says a replay
    /// rejection by application code is not sufficient evidence. The forward-
    /// secrecy claim is about key material, so the failure has to come from
    /// OpenMLS's secret tree and the test has to be able to see the exact chain
    /// `ProcessMessageError::ValidationError` →
    /// `ValidationError::UnableToDecrypt` →
    /// `MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)`.
    ///
    /// The transaction is always rolled back, so an attempt — successful or not
    /// — never mutates the snapshot and a positive control can be run after a
    /// negative one without ordering effects.
    pub fn try_process_message(
        &mut self,
        group_id: ProtoGroupId,
        message: ProtocolMessage,
    ) -> Result<Result<ProcessedMessage, ProcessMessageError<rusqlite::Error>>, StoreError> {
        let transaction = self.connection.transaction()?;
        let outcome = {
            let provider = StoreProvider::new(&transaction);
            let mut group =
                DmGroup::load(&provider, &group_id, None)?.ok_or(StoreError::UnknownGroup)?;
            group.mls_group_mut().process_message(&provider, message)
        };
        transaction.rollback()?;
        Ok(outcome)
    }

    /// Every byte of the snapshot's database file, for a plaintext scan.
    pub fn raw_database_bytes(path: &Path) -> Result<Vec<u8>, StoreError> {
        std::fs::read(path).map_err(|error| StoreError::io(path, error))
    }
}
