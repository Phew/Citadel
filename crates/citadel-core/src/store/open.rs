//! Keying and connection hardening (ADR-0007 §3, as amended by Amendment 1
//! §§A.5 and A.6).
//!
//! Every connection is keyed through SQLCipher's programmatic key API before
//! any schema access, using only the canonical raw-key representation. Then
//! every required setting is **set and read back**, and a failure to enable *or*
//! to verify any one of them aborts opening the store. There is no "best
//! effort" setting here and no silently skipped check: Amendment 1 §A.5's
//! standing rule is that a flag the shipped bundle does not honor is a build
//! failure and an escalation.
//!
//! ## The codec verification, on the staged 4.5.7 bundle
//!
//! ADR-0007 §3 originally verified an active codec with `PRAGMA cipher_status`.
//! That pragma is SQLCipher 4.12.0+ and is absent from the shipped 4.5.7
//! amalgamation (independently confirmed: zero occurrences of `cipher_status`
//! in `libsqlite3-sys-0.30.1/sqlcipher/sqlite3.c`, while `cipher_version`,
//! `cipher_provider`, `cipher_integrity_check` and `cipher_memory_security` are
//! all present). Amendment 1 §A.6 respecifies the sequence, and this module
//! implements exactly that:
//!
//! 1. `PRAGMA cipher_version` is exactly `4.5.7 community`;
//! 2. `PRAGMA cipher_provider` is `openssl` — Amendment 1 §A.1 established that
//!    SQLCipher selects OpenSSL by **compiled default** rather than by a flag
//!    the build script passes, so this must be proved by readback and never
//!    assumed;
//! 3. successful encrypted schema access — the load-bearing, version-independent
//!    codec proof, since a connection whose codec is inactive or wrongly keyed
//!    cannot read the schema at all;
//! 4. `cipher_integrity_check` at first creation and the other points §3 names.
//!
//! ## Extension loading (docs/issues/011 N1)
//!
//! Staging removed Citadel's control of `libsqlite3-sys`'s build script, so
//! `SQLITE_OMIT_LOAD_EXTENSION` cannot be honored: the stock build compiles
//! `-DSQLITE_ENABLE_LOAD_EXTENSION=1` (`build.rs:131`). Amendment 1 §A.5 said
//! the open sequence "asserts the flag is off" without naming a mechanism, and
//! an unnamed assertion is not evidence. The named mechanism is
//! [`probe_extension_loading_is_refused`]: a **behavioral** probe that calls
//! `load_extension()` on the live connection and requires it to fail with
//! `not authorized`.
//!
//! That message is not incidental. In the shipped amalgamation, `loadExt`
//! returns exactly `"not authorized"` when `SQLITE_LoadExtFunc` is clear
//! (`sqlcipher/sqlite3.c:135068-135074`), and that flag is set only by an
//! explicit `sqlite3_enable_load_extension` call (`:142378`). If the flag were
//! ever on, the probe's nonexistent extension name would fail with a *loader*
//! error instead, so the probe distinguishes "refused" from "attempted and
//! missing" rather than merely observing an error.
//!
//! rusqlite 0.32.1 additionally gates `load_extension_enable` behind a
//! `load_extension` feature it does not enable by default (it declares no
//! default features at all), so the safe enabling API is not even compiled on
//! this graph. That strengthens the position but does not replace the probe:
//! the probe's value is that it keeps holding if a future dependency change
//! quietly enables that feature.

use super::error::StoreError;
use super::key::DatabaseEncryptionKey;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// `PRAGMA cipher_version` on the staged bundle. Amendment 1 §A.7 pins the
/// value; the format is `"<number> <build>"` because the stock amalgamation
/// leaves `CIPHER_VERSION_QUALIFIER` undefined (`sqlite3.c:108549-108555`).
pub const EXPECTED_CIPHER_VERSION: &str = "4.5.7 community";

/// `PRAGMA cipher_provider` on the staged bundle
/// (`sqlcipher_openssl_get_provider_name`, `sqlite3.c:110702-110703`).
pub const EXPECTED_CIPHER_PROVIDER: &str = "openssl";

/// The name the extension-loading probe tries to load. It does not exist, and
/// must not: if the probe ever reached the loader, a real name could succeed.
const EXTENSION_PROBE_NAME: &str = "citadel-store-extension-loading-probe";

/// Whether the connection is creating a database or opening an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIntent {
    /// First-run creation of a database that must not already exist.
    Create,
    /// Open an existing database.
    Existing,
}

/// Open, key, and harden one connection, or fail closed.
///
/// On success the connection has been proved to have an active SQLCipher codec
/// of the pinned version and provider, has every ADR-0007 §3 setting verified by
/// readback, and has been proved unable to load extensions.
pub fn open_hardened(
    path: &Path,
    key: &DatabaseEncryptionKey,
    intent: OpenIntent,
) -> Result<Connection, StoreError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        // Enforced by the unix VFS only. `unixFullPathname` is the sole producer
        // of SQLITE_OK_SYMLINK (`:44874`, returned at `:44897`), and the flag is
        // honored in exactly one place, on receiving it (`:61795-61797`).
        // `winFullPathname` (`:52228`) never returns it, so this flag is INERT on
        // Windows and containment there rests on ProfilePaths::validate's
        // by-path reparse-point check. See docs/issues/012.
        //
        // Line numbers are in `libsqlite3-sys-0.30.1/sqlcipher/sqlite3.c` — the
        // SQLCipher 4.5.7 amalgamation this crate compiles, selected by that
        // crate's `build.rs:143`. The package also ships an unrelated
        // `sqlite3/sqlite3.c` whose line numbering differs by roughly 200 lines
        // here; every `sqlite3.c` citation in this repository means the
        // `sqlcipher/` tree.
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    if intent == OpenIntent::Create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    // URI filenames stay off: they would let a path carry query parameters that
    // change VFS behaviour, and every store path is fixed anyway.
    let connection = Connection::open_with_flags(path, flags)?;

    // Set BEFORE keying, deliberately. `sqlcipher_get_mem_security` reports
    // enabled only when the pragma is on AND SQLCipher's allocator has already
    // run (`sqlite3.c:109000-109004`), and the codec context allocation during
    // keying is what runs it. Setting this after `PRAGMA key` would read back 0
    // and abort a correctly configured store.
    connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;

    // The one place the key is encoded, in the canonical raw-key form, so
    // SQLCipher bypasses its passphrase KDF. The literal lives in a zeroizing
    // owner for the whole statement.
    let literal = key.raw_key_literal();
    connection
        .execute_batch(&format!("PRAGMA key = \"{}\";", &*literal))
        .map_err(StoreError::StoreUnreadable)?;
    drop(literal);

    verify_codec(&connection)?;
    verify_schema_access(&connection)?;
    apply_and_verify_settings(&connection)?;
    probe_extension_loading_is_refused(&connection)?;

    Ok(connection)
}

/// Steps 1 and 2 of Amendment 1 §A.6.
fn verify_codec(connection: &Connection) -> Result<(), StoreError> {
    let version: String =
        connection.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
    if version.trim() != EXPECTED_CIPHER_VERSION {
        return Err(StoreError::not_verified(
            "cipher_version",
            EXPECTED_CIPHER_VERSION,
            version,
        ));
    }
    let provider: String =
        connection.pragma_query_value(None, "cipher_provider", |row| row.get(0))?;
    if provider.trim() != EXPECTED_CIPHER_PROVIDER {
        return Err(StoreError::not_verified(
            "cipher_provider",
            EXPECTED_CIPHER_PROVIDER,
            provider,
        ));
    }
    Ok(())
}

/// Step 3 of Amendment 1 §A.6: the load-bearing codec proof.
///
/// A wrong key, a corrupt page, a plaintext SQLite file, or an unsupported
/// SQLCipher format all land here, and all of them are
/// [`StoreError::StoreUnreadable`] — never an empty-store reset.
fn verify_schema_access(connection: &Connection) -> Result<(), StoreError> {
    connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|_| ())
        .map_err(StoreError::StoreUnreadable)
}

/// Every setting ADR-0007 §3 requires, each set and then read back.
fn apply_and_verify_settings(connection: &Connection) -> Result<(), StoreError> {
    // `journal_mode = DELETE` is a security choice, not a performance one: WAL
    // retains prior encrypted page images that stay readable to an attacker who
    // later obtains the current database encryption key. In rollback-journal
    // mode, deleting the journal IS the commit point.
    let journal_mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(StoreError::not_verified(
            "journal_mode",
            "delete",
            journal_mode,
        ));
    }

    set_and_verify_int(connection, "synchronous", "FULL", 2)?;
    set_and_verify_int(connection, "secure_delete", "ON", 1)?;
    set_and_verify_int(connection, "foreign_keys", "ON", 1)?;
    set_and_verify_int(connection, "temp_store", "MEMORY", 2)?;
    set_and_verify_int(connection, "trusted_schema", "OFF", 0)?;

    // Read back only: this was set before keying so the codec allocation could
    // arm SQLCipher's allocator (see `open_hardened`).
    //
    // It comes back as TEXT, not INTEGER: SQLCipher formats the value with
    // `sqlite3_mprintf("%d", ...)` and returns it through
    // `sqlcipher_vdbe_return_string` (`sqlcipher/sqlite3.c:107456-107462`), so
    // asking rusqlite for an i64 fails with InvalidColumnType even when the
    // setting is correct.
    let memory_security = read_cipher_memory_security(connection)?;
    if memory_security != 1 {
        return Err(StoreError::not_verified(
            "cipher_memory_security",
            1,
            memory_security,
        ));
    }

    // DEFENSIVE last among the settings: it is what forecloses the
    // `DBCONFIG_DEFENSIVE`-off precondition of CVE-2026-11822 (Amendment 1
    // §A.4), and Amendment 1 §A.4 leans on it being ON with readback.
    let defensive = connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    if !defensive || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)? {
        return Err(StoreError::not_verified(
            "SQLITE_DBCONFIG_DEFENSIVE",
            "on",
            "off",
        ));
    }
    // `trusted_schema` also has a db-config form; both are checked because the
    // pragma and the db-config are separate switches in SQLite's API surface and
    // Amendment 1 §A.5 leans on this one to block a schema-embedded
    // `load_extension` invocation.
    if connection.db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)? {
        return Err(StoreError::not_verified(
            "SQLITE_DBCONFIG_TRUSTED_SCHEMA",
            "off",
            "on",
        ));
    }
    Ok(())
}

/// Read `PRAGMA cipher_memory_security` as the integer it means.
///
/// SQLCipher returns it as a string, and `sqlcipher_get_mem_security` reports
/// enabled only when the pragma is on **and** SQLCipher's allocator has already
/// run (`sqlite3.c:109000-109004`) — which is why the pragma is set before
/// keying and only read back afterwards.
pub fn read_cipher_memory_security(connection: &Connection) -> Result<i64, StoreError> {
    let raw: String =
        connection.pragma_query_value(None, "cipher_memory_security", |row| row.get(0))?;
    raw.trim()
        .parse::<i64>()
        .map_err(|_| StoreError::not_verified("cipher_memory_security", "0 or 1", raw.clone()))
}

fn set_and_verify_int(
    connection: &Connection,
    pragma: &'static str,
    value: &str,
    expected: i64,
) -> Result<(), StoreError> {
    connection.pragma_update(None, pragma, value)?;
    let actual: i64 = connection.pragma_query_value(None, pragma, |row| row.get(0))?;
    if actual != expected {
        return Err(StoreError::not_verified(pragma, expected, actual));
    }
    Ok(())
}

/// docs/issues/011 N1: prove, behaviorally, that extension loading is off.
///
/// Requiring the exact `not authorized` refusal is what makes this evidence
/// rather than an assertion. Any other outcome — success, or a loader error
/// reporting that the extension could not be found — means the connection
/// reached the loader, which means the flag was set.
pub fn probe_extension_loading_is_refused(connection: &Connection) -> Result<(), StoreError> {
    let outcome =
        connection.query_row("SELECT load_extension(?1)", [EXTENSION_PROBE_NAME], |row| {
            row.get::<_, Option<String>>(0)
        });
    match outcome {
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message.contains("not authorized") =>
        {
            Ok(())
        }
        Err(rusqlite::Error::SqliteFailure(_, Some(message))) => Err(StoreError::not_verified(
            "load_extension",
            "refused with \"not authorized\"",
            format!("reached the loader: {message}"),
        )),
        Err(other) => Err(StoreError::not_verified(
            "load_extension",
            "refused with \"not authorized\"",
            format!("{other}"),
        )),
        Ok(_) => Err(StoreError::not_verified(
            "load_extension",
            "refused with \"not authorized\"",
            "the call succeeded, so extension loading is ENABLED",
        )),
    }
}

/// Run `cipher_integrity_check` and fail on any reported problem.
///
/// ADR-0007 §3 runs this at first creation, on both sides of a pending
/// migration, after recovery of an unclean shutdown, and during explicit
/// maintenance — deliberately **not** on every clean open, because SQLCipher's
/// per-page authentication already fails an ordinary open when an accessed page
/// is corrupt and a full scan on every startup would be a latency cost with no
/// added property.
pub fn cipher_integrity_check(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = connection.prepare("PRAGMA cipher_integrity_check")?;
    let problems: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    if problems.is_empty() {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed(problems.len()))
    }
}

/// Reject a standard, unencrypted SQLite database at the store path.
///
/// ADR-0007 §1: no plaintext database is ever accepted or converted in place;
/// import is M8 work behind a separate accepted design. The check is the
/// 16-byte file header, which is the one thing a plaintext SQLite file always
/// has and an encrypted one never does.
pub fn reject_plaintext_database(path: &Path) -> Result<(), StoreError> {
    use std::io::Read;

    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::io(path, error)),
    };
    let mut header = [0u8; 16];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        // Shorter than a header: not a plaintext database, and whatever it is
        // will fail the codec proof.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(error) => return Err(StoreError::io(path, error)),
    }
    if &header == SQLITE_HEADER {
        return Err(StoreError::PlaintextDatabaseRejected);
    }
    Ok(())
}
