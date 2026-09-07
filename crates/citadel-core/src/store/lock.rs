//! The OS-enforced exclusive profile lock (ADR-0007 §2).
//!
//! One fixed lock file is opened read-write without truncation and locked with
//! `std::fs::File::try_lock`. Rust 1.95 is the workspace minimum, so this is a
//! stable standard-library primitive and the store needs no lock dependency.
//!
//! The handle is owned for the whole actor lifetime and through profile
//! destruction, and it is released last. Lock loss on process death is
//! automatic, which is what makes a crashed profile recoverable without a stale
//! lock file to clean up. Content is deliberately empty: a PID inside the file
//! would be a second source of truth that can disagree with the OS.
//!
//! `TryLockError::WouldBlock` becomes [`StoreError::StoreAlreadyOpen`]; every
//! other lock error is preserved as an I/O failure rather than being flattened
//! into "already open", because the two demand different responses.

use super::error::StoreError;
use super::paths::ProfilePaths;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

/// A held exclusive profile lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct ProfileLock {
    /// Kept for its `Drop`; the OS lock lives with this handle.
    _file: File,
    path: PathBuf,
}

impl ProfileLock {
    /// Acquire the lock, or fail closed.
    pub fn acquire(paths: &ProfilePaths) -> Result<Self, StoreError> {
        let path = paths.lock();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        apply_no_follow(&mut options);
        let file = options
            .open(&path)
            .map_err(|error| StoreError::io(path.clone(), error))?;

        // Validated from the OPEN HANDLE, not from the path: this is what makes
        // the check race-free against a link swapped in after a path check.
        let metadata = file
            .metadata()
            .map_err(|error| StoreError::io(path.clone(), error))?;
        if !metadata.is_file() {
            return Err(StoreError::StorePathRejected(path));
        }

        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file, path }),
            // Contention, and only contention, is "already open".
            Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::StoreAlreadyOpen(path)),
            // Everything else stays an I/O failure. Flattening a permission or
            // filesystem error into "already open" would send a caller looking
            // for another process that does not exist.
            Err(std::fs::TryLockError::Error(error)) => Err(StoreError::io(path, error)),
        }
    }

    /// The lock file's path, for destruction's residual report.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[cfg(unix)]
fn apply_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    // Refuses to open the lock at all if it is a symbolic link.
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn apply_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: opens the reparse point itself rather
    /// than its target, so the `is_file` check below sees the link.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_acquisition_in_this_process_reports_already_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        paths.prepare().expect("prepare");

        let first = ProfileLock::acquire(&paths).expect("first lock");
        let second = ProfileLock::acquire(&paths);
        assert!(
            matches!(second, Err(StoreError::StoreAlreadyOpen(_))),
            "{second:?}"
        );
        drop(first);
        ProfileLock::acquire(&paths).expect("lock is reacquirable after release");
    }

    #[test]
    fn the_lock_carries_no_meaning_in_its_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        paths.prepare().expect("prepare");
        std::fs::write(paths.lock(), b"stale pid 1234").expect("seed content");

        let lock = ProfileLock::acquire(&paths).expect("lock");
        let path = lock.path().clone();
        // The lock is an OS lock, not a file whose contents mean anything. It is
        // opened WITHOUT truncation, so pre-existing bytes survive untouched —
        // and the store never reads them, so a stale PID from an older tool
        // cannot influence anything. Content is only readable after release,
        // because Windows byte-range locks block a read while it is held.
        drop(lock);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"stale pid 1234",
            "acquiring the lock must not rewrite or truncate the file"
        );
    }

    #[test]
    fn a_directory_at_the_lock_path_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ProfilePaths::at_root(dir.path());
        paths.prepare().expect("prepare");
        std::fs::create_dir(paths.lock()).expect("decoy directory");
        let result = ProfileLock::acquire(&paths);
        assert!(result.is_err(), "a directory must not lock as a profile");
    }
}
