//! The application schema, its migrations, and the store metadata
//! (ADR-0007 §§1, 4, 5).
//!
//! Application migrations use their own named history table,
//! `citadel_app_migrations`, kept separate from the upstream provider's
//! `openmls_sqlite_storage_migrations` in the same encrypted database. Both run
//! only **after** successful key and integrity verification, both are
//! transactional, and neither resets user state on failure.
//!
//! A database at a newer application schema version than this build fails
//! closed. So does an unknown codec identifier or an unknown bound-version
//! tuple: ADR-0007 §1 forbids trial decoding and silent fallback between
//! codecs, so an unrecognised identifier can only mean "a build that is not
//! this one wrote these rows".
//!
//! Migrations are immutable after release. Editing a statement below rather
//! than adding a new version would leave already-created databases silently
//! different from freshly created ones, which no `PRAGMA user_version` check
//! would ever catch.

use super::codec::{CODEC_BOUND_VERSIONS, CODEC_ID};
use super::error::StoreError;
use rusqlite::{Connection, Transaction};

/// The highest application schema version this build implements.
pub const APP_SCHEMA_VERSION: i64 = 1;

/// The value of the `schema_sentinel` metadata row. §3's open sequence requires
/// a schema sentinel in addition to schema access, so that a database that
/// decrypts but is not a Citadel store is refused rather than migrated.
pub const SCHEMA_SENTINEL: &str = "citadel-local-store-v1";

/// Metadata keys in `citadel_store_meta`.
pub mod meta_key {
    /// Proves the decrypted database is a Citadel store.
    pub const SCHEMA_SENTINEL: &str = "schema_sentinel";
    /// The storage codec identifier, written before the first OpenMLS record.
    pub const CODEC_ID: &str = "codec_id";
    /// The exact OpenMLS crate versions the codec identifier is bound to.
    pub const CODEC_BOUND_VERSIONS: &str = "codec_bound_versions";
    /// The application schema version, for fail-closed newer-schema rejection.
    pub const APP_SCHEMA_VERSION: &str = "app_schema_version";
}

/// Ordered, immutable application migrations. Index + 1 is the version.
const MIGRATIONS: [&str; APP_SCHEMA_VERSION as usize] =
    [include_str!("migrations/V1__initial.sql")];

/// Create the migration history table if absent, then apply anything missing.
///
/// Each migration runs in its own transaction with its history row, so a
/// failure leaves the database at the last fully applied version rather than
/// half-way through one.
pub fn run_app_migrations(connection: &mut Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS citadel_app_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             ) STRICT;",
        )
        .map_err(|error| StoreError::Migration(format!("history table: {error}")))?;

    let applied: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM citadel_app_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|error| StoreError::Migration(format!("history read: {error}")))?;

    if applied > APP_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: applied,
            supported: APP_SCHEMA_VERSION,
        });
    }

    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let version = index as i64 + 1;
        if version <= applied {
            continue;
        }
        let transaction = connection
            .transaction()
            .map_err(|error| StoreError::Migration(format!("v{version} begin: {error}")))?;
        transaction
            .execute_batch(sql)
            .map_err(|error| StoreError::Migration(format!("v{version}: {error}")))?;
        transaction
            .execute(
                "INSERT INTO citadel_app_migrations (version, applied_at) VALUES (?1, ?2)",
                rusqlite::params![version, now_unix_seconds()],
            )
            .map_err(|error| StoreError::Migration(format!("v{version} history: {error}")))?;
        transaction
            .commit()
            .map_err(|error| StoreError::Migration(format!("v{version} commit: {error}")))?;
    }
    Ok(())
}

/// Write the sentinel, codec identifier, bound-version tuple, and schema
/// version. ADR-0007 §1 requires the codec identifier and version tuple to be
/// written **before the first OpenMLS record**, so this runs during first-run
/// creation, before the provider is ever handed a group.
pub fn write_store_metadata(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    for (key, value) in [
        (meta_key::SCHEMA_SENTINEL, SCHEMA_SENTINEL.to_string()),
        (meta_key::CODEC_ID, CODEC_ID.to_string()),
        (
            meta_key::CODEC_BOUND_VERSIONS,
            CODEC_BOUND_VERSIONS.to_string(),
        ),
        (meta_key::APP_SCHEMA_VERSION, APP_SCHEMA_VERSION.to_string()),
    ] {
        transaction.execute(
            "INSERT INTO citadel_store_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
    }
    Ok(())
}

/// Read one metadata value, or `None` if absent.
pub fn read_metadata(connection: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    let value = connection
        .query_row(
            "SELECT value FROM citadel_store_meta WHERE key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    Ok(value)
}

/// Verify the sentinel, codec identity, and schema version of an opened store.
///
/// Fails closed on anything unrecognised. There is deliberately no "upgrade the
/// metadata to what this build expects" path: a future codec migration must
/// retain the old decoder, decode every old provider row, re-encode it, and
/// update the identifier **last**, in one transaction.
pub fn verify_store_identity(connection: &Connection) -> Result<(), StoreError> {
    let sentinel = read_metadata(connection, meta_key::SCHEMA_SENTINEL)?;
    match sentinel.as_deref() {
        Some(SCHEMA_SENTINEL) => {}
        other => {
            return Err(StoreError::not_verified(
                "schema_sentinel",
                SCHEMA_SENTINEL,
                other.unwrap_or("<absent>"),
            ))
        }
    }

    let codec = read_metadata(connection, meta_key::CODEC_ID)?;
    if codec.as_deref() != Some(CODEC_ID) {
        return Err(StoreError::UnsupportedCodec {
            found: codec.unwrap_or_else(|| "<absent>".into()),
            expected: CODEC_ID.to_string(),
        });
    }

    let bound = read_metadata(connection, meta_key::CODEC_BOUND_VERSIONS)?;
    if bound.as_deref() != Some(CODEC_BOUND_VERSIONS) {
        return Err(StoreError::UnsupportedCodec {
            found: bound.unwrap_or_else(|| "<absent>".into()),
            expected: CODEC_BOUND_VERSIONS.to_string(),
        });
    }

    let version = read_metadata(connection, meta_key::APP_SCHEMA_VERSION)?
        .and_then(|raw| raw.parse::<i64>().ok())
        .unwrap_or(0);
    if version > APP_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: version,
            supported: APP_SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Seconds since the Unix epoch, saturating at 0 before it.
pub(crate) fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
