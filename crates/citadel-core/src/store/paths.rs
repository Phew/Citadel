//! Fixed profile paths and their containment rules (ADR-0007 §2).
//!
//! Every file the store touches — the database, the staging database, the
//! SQLite sidecars, and the lock — has a **fixed** name inside one profile
//! directory. Nothing is caller-supplied at runtime, so there is no path
//! parameter for an attacker to influence, and destruction has a closed
//! enumeration to report residuals against.
//!
//! ## What the containment check does and does not promise
//!
//! Before any credential-store or database operation, the profile directory and
//! each fixed path are checked with `symlink_metadata`: the directory must be a
//! real directory and each existing path must be a regular file, so a symbolic
//! link or a Windows reparse point at any of them is refused rather than
//! followed. The lock itself is additionally opened with `O_NOFOLLOW` on Unix
//! and `FILE_FLAG_OPEN_REPARSE_POINT` on Windows and re-validated **from the
//! open handle**, which is link-race-free.
//!
//! The database is opened by SQLite from a path, so its check is by path and a
//! substitution racing between the check and the open is not excluded by the
//! check alone. What excludes it in practice is the ordering: the exclusive
//! profile lock is acquired first, through the handle-validated path, and held
//! for the whole actor lifetime. That is the honest scope — a handle-validated
//! lock plus a path-validated database, not a handle-validated database.

use super::error::StoreError;
use std::path::{Path, PathBuf};

/// The final encrypted database.
pub const DATABASE_FILE: &str = "citadel.db";
/// The first-run staging database, beside the final one.
pub const STAGING_FILE: &str = "citadel.db.staging";
/// The exclusive profile lock.
pub const LOCK_FILE: &str = "citadel.lock";

/// Every SQLite sidecar the engine can create beside `citadel.db`.
///
/// `journal_mode = DELETE` means only `-journal` occurs in normal operation.
/// The WAL pair is enumerated anyway because destruction and the disk-copy
/// evidence must cover files a *previous* or *future* configuration could have
/// left, not only the ones this configuration creates. An enumeration that only
/// listed what today's settings produce would be exactly the kind of check that
/// passes while leaving ciphertext behind.
pub const SIDECAR_SUFFIXES: [&str; 4] = ["-journal", "-wal", "-shm", "-journal.tmp"];

/// The fixed set of paths belonging to one local profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    root: PathBuf,
}

impl ProfilePaths {
    /// The profile directory for the current OS user, per platform convention.
    ///
    /// Windows uses `%LOCALAPPDATA%` rather than `%APPDATA%` deliberately: the
    /// roaming profile would carry an encrypted database to another machine
    /// while `CRED_PERSIST_LOCAL_MACHINE` kept its key behind, which is a
    /// confusing half-move, and ADR-0007 §2 forbids roaming for the key.
    pub fn platform_default() -> Result<Self, StoreError> {
        let base = platform_data_dir()?;
        Ok(Self {
            root: base.join("Citadel").join("profile-v1"),
        })
    }

    /// A profile rooted at an explicit directory.
    ///
    /// Test-configuration only. Production always uses
    /// [`ProfilePaths::platform_default`], so there is no runtime setting, no
    /// environment variable, and no command-line flag that relocates a live
    /// profile out of the platform application-data directory.
    #[cfg(any(test, feature = "testing"))]
    pub fn at_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The profile directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The final encrypted database.
    pub fn database(&self) -> PathBuf {
        self.root.join(DATABASE_FILE)
    }

    /// The first-run staging database.
    pub fn staging(&self) -> PathBuf {
        self.root.join(STAGING_FILE)
    }

    /// The exclusive profile lock.
    pub fn lock(&self) -> PathBuf {
        self.root.join(LOCK_FILE)
    }

    /// The rollback journal for the final database.
    ///
    /// In `journal_mode = DELETE`, this file's presence at startup means the
    /// previous run did not shut down cleanly, and deleting it is SQLite's
    /// commit point.
    pub fn journal(&self) -> PathBuf {
        self.root.join(format!("{DATABASE_FILE}-journal"))
    }

    /// Every SQLite sidecar path for the final database.
    pub fn sidecars(&self) -> Vec<PathBuf> {
        SIDECAR_SUFFIXES
            .iter()
            .map(|suffix| self.root.join(format!("{DATABASE_FILE}{suffix}")))
            .collect()
    }

    /// Every sidecar path for the staging database.
    pub fn staging_sidecars(&self) -> Vec<PathBuf> {
        SIDECAR_SUFFIXES
            .iter()
            .map(|suffix| self.root.join(format!("{STAGING_FILE}{suffix}")))
            .collect()
    }

    /// Every file this profile can own, for destruction and snapshot copying.
    /// Closed enumeration: database, staging, both sidecar sets, and the lock.
    pub fn all_files(&self) -> Vec<PathBuf> {
        let mut all = vec![self.database(), self.staging()];
        all.extend(self.sidecars());
        all.extend(self.staging_sidecars());
        all.push(self.lock());
        all
    }

    /// Create the profile directory if absent, then validate containment.
    pub fn prepare(&self) -> Result<(), StoreError> {
        if !self.root.exists() {
            std::fs::create_dir_all(&self.root)
                .map_err(|error| StoreError::io(self.root.clone(), error))?;
        }
        self.validate()
    }

    /// Refuse a profile directory that is not a real directory, and any fixed
    /// path that exists as something other than a regular file.
    pub fn validate(&self) -> Result<(), StoreError> {
        let metadata = std::fs::symlink_metadata(&self.root)
            .map_err(|error| StoreError::io(self.root.clone(), error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StoreError::StorePathRejected(self.root.clone()));
        }
        for path in self.all_files() {
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(StoreError::StorePathRejected(path));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::io(path, error)),
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn platform_data_dir() -> Result<PathBuf, StoreError> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or(StoreError::StoreStateInconsistent(
            "LOCALAPPDATA is not set, so there is no platform application-data directory",
        ))
}

#[cfg(target_os = "macos")]
fn platform_data_dir() -> Result<PathBuf, StoreError> {
    std::env::var_os("HOME")
        .map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
        })
        .ok_or(StoreError::StoreStateInconsistent(
            "HOME is not set, so there is no platform application-data directory",
        ))
}

#[cfg(target_os = "linux")]
fn platform_data_dir() -> Result<PathBuf, StoreError> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        let xdg = PathBuf::from(xdg);
        if xdg.is_absolute() {
            return Ok(xdg);
        }
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local").join("share"))
        .ok_or(StoreError::StoreStateInconsistent(
            "neither XDG_DATA_HOME nor HOME is set, so there is no platform application-data directory",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_path_is_fixed_and_inside_the_profile_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        for path in paths.all_files() {
            assert_eq!(
                path.parent().expect("has a parent"),
                paths.root(),
                "{path:?} escaped the profile directory"
            );
        }
        assert_eq!(paths.database().file_name().unwrap(), DATABASE_FILE);
        assert_eq!(paths.staging().file_name().unwrap(), STAGING_FILE);
        assert_eq!(paths.lock().file_name().unwrap(), LOCK_FILE);
    }

    #[test]
    fn all_files_covers_database_staging_both_sidecar_sets_and_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        let all = paths.all_files();
        // 1 database + 1 staging + 4 sidecars + 4 staging sidecars + 1 lock.
        assert_eq!(all.len(), 11, "{all:?}");
        assert!(all.contains(&paths.database()));
        assert!(all.contains(&paths.staging()));
        assert!(all.contains(&paths.lock()));
        for sidecar in paths.sidecars().into_iter().chain(paths.staging_sidecars()) {
            assert!(all.contains(&sidecar), "{sidecar:?} missing");
        }
    }

    #[test]
    fn a_directory_where_a_store_file_belongs_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        std::fs::create_dir(paths.database()).expect("create decoy directory");
        let result = paths.validate();
        assert!(
            matches!(result, Err(StoreError::StorePathRejected(_))),
            "{result:?}"
        );
    }

    #[test]
    fn prepare_creates_the_profile_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("nested").join("profile");
        let paths = ProfilePaths::at_root(&root);
        paths.prepare().expect("prepare");
        assert!(root.is_dir());
    }
}
