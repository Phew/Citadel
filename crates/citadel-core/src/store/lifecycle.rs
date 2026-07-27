//! First-run creation, the startup state machine, and profile destruction
//! (ADR-0007 §§2 and 6).
//!
//! ## Why creation stages
//!
//! A database that is created, keyed, migrated, and integrity-checked *in
//! place* has a window in which the final path holds a half-built store. The
//! staging path removes that window: everything happens beside the final path,
//! and the last step is a durable rename. A crash therefore leaves either
//! nothing, or an orphan staging file, or a fully built database — never a
//! usable plaintext database and never a half-migrated final one.
//!
//! The credential entry is written **and read back** before installation, so
//! the state "database installed, key unwritable" cannot be reached by an
//! ordinary sequence.
//!
//! ## The startup state machine
//!
//! Exactly ADR-0007 §2's table, and [`StartupState::classify`] is written to
//! mirror its rows one for one so a reader can diff them:
//!
//! | Final | Staging | Key entry | Result |
//! |---|---|---|---|
//! | absent | absent | absent | clean first creation |
//! | absent | present | absent | remove the unreadable orphan staging file, then create |
//! | absent | absent | present | `StoreStateInconsistent`; no automatic deletion |
//! | absent | present | present | validate with the key, recover any hot journal, close and sync, finish installation |
//! | present | any | absent | `StoreKeyMissing`; no replacement key |
//! | present | absent | present | validate and open the final database |
//! | present | present | present | validate the final database, then remove the stale staging file |

use super::credentials::{CredentialStore, SecretItem};
use super::error::StoreError;
use super::key::DatabaseEncryptionKey;
use super::open::{cipher_integrity_check, open_hardened, reject_plaintext_database, OpenIntent};
use super::paths::ProfilePaths;
use super::schema::{run_app_migrations, verify_store_identity, write_store_metadata};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// One row of ADR-0007 §2's startup state table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupState {
    /// No final database, no staging file, no key entry.
    CleanFirstCreation,
    /// An orphan staging file with no key entry: unreadable, so it is removed
    /// and creation proceeds.
    OrphanStagingThenCreate,
    /// A key entry with neither database. Never resolved automatically.
    KeyWithoutDatabase,
    /// An interrupted first run whose key was already written: finish it.
    ResumeInstallation,
    /// A database with no key entry. Never resolved by generating a key.
    DatabaseWithoutKey,
    /// The ordinary case.
    OpenExisting,
    /// The ordinary case, plus a stale staging file to remove.
    OpenExistingAndRemoveStaleStaging,
}

impl StartupState {
    /// Classify from the three observations. Deliberately total and free of
    /// I/O, so the table can be tested directly.
    pub fn classify(final_present: bool, staging_present: bool, key_present: bool) -> Self {
        match (final_present, staging_present, key_present) {
            (false, false, false) => StartupState::CleanFirstCreation,
            (false, true, false) => StartupState::OrphanStagingThenCreate,
            (false, false, true) => StartupState::KeyWithoutDatabase,
            (false, true, true) => StartupState::ResumeInstallation,
            // "present | any | absent" — one row, both staging cases.
            (true, _, false) => StartupState::DatabaseWithoutKey,
            (true, false, true) => StartupState::OpenExisting,
            (true, true, true) => StartupState::OpenExistingAndRemoveStaleStaging,
        }
    }
}

/// An opened store: the hardened connection and the key that opened it.
pub struct OpenedStore {
    /// The keyed, hardened connection.
    pub connection: Connection,
    /// The key in use, retained so evidence and destruction paths need not
    /// re-read the credential store.
    pub key: DatabaseEncryptionKey,
}

/// Run the startup state machine and return an opened, hardened store.
pub fn open_or_create(
    paths: &ProfilePaths,
    credentials: &dyn CredentialStore,
) -> Result<OpenedStore, StoreError> {
    paths.validate()?;
    let final_path = paths.database();
    let staging_path = paths.staging();

    // A plaintext SQLite header at the store path is refused before anything
    // else looks at it (ADR-0007 §1). Doing this first means an import attempt
    // gets a precise error instead of a codec failure.
    reject_plaintext_database(&final_path)?;

    let key_entry = credentials.read(SecretItem::DatabaseEncryptionKey)?;
    let state = StartupState::classify(
        final_path.exists(),
        staging_path.exists(),
        key_entry.is_some(),
    );

    match state {
        StartupState::DatabaseWithoutKey => Err(StoreError::StoreKeyMissing),
        StartupState::KeyWithoutDatabase => Err(StoreError::StoreStateInconsistent(
            "a database encryption key entry exists but neither the final nor the staging \
             database does; this needs an explicit reset or recovery action",
        )),
        StartupState::CleanFirstCreation => create_new(paths, credentials),
        StartupState::OrphanStagingThenCreate => {
            // No key entry ever existed for it, so it cannot be read by anyone,
            // including us. Removing it is not data loss.
            remove_file_and_sidecars(&staging_path, &paths.staging_sidecars())?;
            create_new(paths, credentials)
        }
        StartupState::ResumeInstallation => {
            let key = DatabaseEncryptionKey::from_bytes(key_entry.expect("present in this row"));
            // Validate the staging database with the real key before installing
            // it. Opening it is also what lets SQLite roll back a hot journal.
            {
                let connection = open_hardened(&staging_path, &key, OpenIntent::Existing)?;
                cipher_integrity_check(&connection)?;
                verify_store_identity(&connection)?;
                // Dropping closes the connection, which is what guarantees no
                // live journal remains before the rename.
            }
            fsync_path(&staging_path)?;
            install_staged_database(&staging_path, &final_path)?;
            open_existing(paths, key)
        }
        StartupState::OpenExisting => {
            let key = DatabaseEncryptionKey::from_bytes(key_entry.expect("present in this row"));
            open_existing(paths, key)
        }
        StartupState::OpenExistingAndRemoveStaleStaging => {
            let key = DatabaseEncryptionKey::from_bytes(key_entry.expect("present in this row"));
            // Validate the FINAL database first; only then discard the staging
            // file. The other order would delete the fallback before knowing the
            // survivor is good.
            let opened = open_existing(paths, key)?;
            remove_file_and_sidecars(&staging_path, &paths.staging_sidecars())?;
            Ok(opened)
        }
    }
}

fn open_existing(
    paths: &ProfilePaths,
    key: DatabaseEncryptionKey,
) -> Result<OpenedStore, StoreError> {
    // A rollback journal present before the open means the previous run did not
    // shut down cleanly. SQLite rolls it back during the open; the full scan
    // afterwards is ADR-0007 §3's "after recovery of an unclean shutdown" case.
    let had_hot_journal = paths.journal().exists();
    let mut connection = open_hardened(&paths.database(), &key, OpenIntent::Existing)?;
    // ADR-0007 §3 runs the full scan after recovery of an unclean shutdown, and
    // NOT on every clean open: SQLCipher's per-page authentication already fails
    // an ordinary open when an accessed page is corrupt.
    if had_hot_journal {
        cipher_integrity_check(&connection)?;
    }
    verify_store_identity(&connection)?;
    run_app_migrations(&mut connection)?;
    run_provider_migrations(&mut connection)?;
    Ok(OpenedStore { connection, key })
}

/// Build a complete store at the staging path, write and read back its key,
/// then install it durably.
fn create_new(
    paths: &ProfilePaths,
    credentials: &dyn CredentialStore,
) -> Result<OpenedStore, StoreError> {
    let staging_path = paths.staging();
    let final_path = paths.database();
    if final_path.exists() {
        return Err(StoreError::StoreStateInconsistent(
            "the final database appeared while first-run creation was starting",
        ));
    }

    let key = DatabaseEncryptionKey::generate()
        .map_err(|error| StoreError::Migration(error.to_string()))?;

    // Exclusive creation with per-user permissions, before SQLite ever sees the
    // path: `create_new` fails if anything is already there, which closes the
    // window where another process could pre-place a file we would then key.
    create_exclusive_private_file(&staging_path)?;

    {
        let mut connection = open_hardened(&staging_path, &key, OpenIntent::Create)?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(include_str!("migrations/V1__initial.sql"))?;
        transaction.execute(
            "CREATE TABLE IF NOT EXISTS citadel_app_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             ) STRICT",
            [],
        )?;
        transaction.execute(
            "INSERT INTO citadel_app_migrations (version, applied_at) VALUES (1, ?1)",
            [super::schema::now_unix_seconds()],
        )?;
        // The codec identifier and bound-version tuple are written HERE, before
        // the provider migrations create any OpenMLS table and therefore before
        // any OpenMLS record can exist (ADR-0007 §1).
        write_store_metadata(&transaction)?;
        transaction.commit()?;

        run_provider_migrations(&mut connection)?;
        cipher_integrity_check(&connection)?;
        // Closed with no live journal before the file is synced.
    }
    fsync_path(&staging_path)?;

    // Written and READ BACK before installation: an unwritable or unreadable
    // credential store must fail while the final path is still absent.
    credentials.write(SecretItem::DatabaseEncryptionKey, key.as_bytes())?;
    let readback = credentials.read(SecretItem::DatabaseEncryptionKey)?.ok_or(
        StoreError::StoreStateInconsistent(
            "the database encryption key was written but read back absent",
        ),
    )?;
    if readback.as_slice() != key.as_bytes() {
        return Err(StoreError::StoreStateInconsistent(
            "the database encryption key read back with different bytes than were written",
        ));
    }

    install_staged_database(&staging_path, &final_path)?;
    open_existing(paths, key)
}

/// Run the upstream OpenMLS provider's own migrations, in their own named
/// history table (`openmls_sqlite_storage_migrations`), separate from the
/// application's.
fn run_provider_migrations(connection: &mut Connection) -> Result<(), StoreError> {
    use super::codec::CitadelOpenMlsJsonCodecV1;
    use openmls_sqlite_storage::SqliteStorageProvider;

    let mut provider =
        SqliteStorageProvider::<CitadelOpenMlsJsonCodecV1, &mut Connection>::new(connection);
    provider
        .run_migrations()
        .map_err(|error| StoreError::Migration(format!("openmls provider: {error}")))
}

/// Create a file that must not already exist, readable and writable only by the
/// current user where the platform expresses that in file mode.
fn create_exclusive_private_file(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // On Windows the file inherits the profile directory's ACL, which is under
    // %LOCALAPPDATA% and therefore already per-user. There is no mode bit to
    // set, and pretending otherwise would be the kind of claim this lane keeps
    // getting caught making.
    let file = options
        .open(path)
        .map_err(|error| StoreError::io(path, error))?;
    file.sync_all()
        .map_err(|error| StoreError::io(path, error))?;
    Ok(())
}

/// Flush a file's contents and metadata to disk.
///
/// Opened for WRITING even though nothing is written: Windows'
/// `FlushFileBuffers` requires write access on the handle and fails a read-only
/// one with `ERROR_ACCESS_DENIED`, which would turn a durability step into a
/// spurious failure on one platform only.
fn fsync_path(path: &Path) -> Result<(), StoreError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| StoreError::io(path, error))?;
    file.sync_all().map_err(|error| StoreError::io(path, error))
}

/// Move the staged database onto the final path durably.
#[cfg(unix)]
fn install_staged_database(staging: &Path, final_path: &Path) -> Result<(), StoreError> {
    std::fs::rename(staging, final_path).map_err(|error| StoreError::io(final_path, error))?;
    // The rename itself is atomic, but the DIRECTORY ENTRY is not durable until
    // the parent directory is synced. Without this, a power loss can leave the
    // new name absent even though the data is on disk.
    let parent = final_path.parent().unwrap_or(Path::new("."));
    let dir = std::fs::File::open(parent).map_err(|error| StoreError::io(parent, error))?;
    dir.sync_all()
        .map_err(|error| StoreError::io(parent, error))
}

/// Move the staged database onto the final path durably.
#[cfg(windows)]
fn install_staged_database(staging: &Path, final_path: &Path) -> Result<(), StoreError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let wide = |path: &Path| -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let from = wide(staging);
    let to = wide(final_path);
    // MOVEFILE_WRITE_THROUGH does not set MOVEFILE_REPLACE_EXISTING: the final
    // path must not already exist, and this call failing on an existing target
    // is the behaviour ADR-0007 §2 wants.
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        return Err(StoreError::io(final_path, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn remove_file_and_sidecars(path: &Path, sidecars: &[PathBuf]) -> Result<(), StoreError> {
    for target in std::iter::once(path).chain(sidecars.iter().map(|p| p.as_path())) {
        match std::fs::remove_file(target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::io(target, error)),
        }
    }
    Ok(())
}

/// What local profile destruction actually managed to do (ADR-0007 §6).
///
/// Destruction attempts **every** deletion and reports structured partial
/// failure rather than stopping at the first error, because stopping early is
/// how residual ciphertext and a live key survive a "failed" destroy.
#[derive(Debug, Default)]
pub struct DestructionReport {
    /// Credential entries whose deletion failed, with the reason.
    pub credential_failures: Vec<(&'static str, String)>,
    /// Files still present after every removal was attempted.
    pub residual_paths: Vec<PathBuf>,
}

impl DestructionReport {
    /// Destruction succeeded only when all three credentials and all files are
    /// confirmed absent. An entry or path that was already absent satisfies it.
    pub fn is_complete(&self) -> bool {
        self.credential_failures.is_empty() && self.residual_paths.is_empty()
    }
}

/// Delete this profile's three credential entries and every file it owns.
///
/// The caller must have closed the actor first: SQLCipher holds key material
/// for the connection lifetime, so closing is required before destruction.
///
/// Confirmed loss of the database encryption key is **cryptographic erasure**
/// of any residual database file. It is not a claim that the filesystem
/// overwrote every block, and the residual report exists precisely so a caller
/// is not told otherwise.
pub fn destroy_profile(
    paths: &ProfilePaths,
    credentials: &dyn CredentialStore,
    lock_path: &Path,
) -> DestructionReport {
    let mut report = DestructionReport::default();

    for item in SecretItem::ALL {
        if let Err(error) = credentials.delete(item) {
            report
                .credential_failures
                .push((item.item_name(), error.to_string()));
        }
    }

    for path in paths.all_files() {
        // The lock is released last, by dropping its handle after this returns,
        // so its file is not removed here.
        if path == lock_path {
            continue;
        }
        let _ = std::fs::remove_file(&path);
        if path.exists() {
            report.residual_paths.push(path);
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_table_matches_adr_0007_section_2_row_for_row() {
        use StartupState::*;
        //                    final  staging  key
        assert_eq!(
            StartupState::classify(false, false, false),
            CleanFirstCreation
        );
        assert_eq!(
            StartupState::classify(false, true, false),
            OrphanStagingThenCreate
        );
        assert_eq!(
            StartupState::classify(false, false, true),
            KeyWithoutDatabase
        );
        assert_eq!(
            StartupState::classify(false, true, true),
            ResumeInstallation
        );
        // "present | any | absent" is ONE row and both staging cases take it.
        assert_eq!(
            StartupState::classify(true, false, false),
            DatabaseWithoutKey
        );
        assert_eq!(
            StartupState::classify(true, true, false),
            DatabaseWithoutKey
        );
        assert_eq!(StartupState::classify(true, false, true), OpenExisting);
        assert_eq!(
            StartupState::classify(true, true, true),
            OpenExistingAndRemoveStaleStaging
        );
    }
}
