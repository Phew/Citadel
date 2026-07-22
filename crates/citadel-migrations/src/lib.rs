//! citadel-migrations: the canonical migration corpus and runner for the
//! shared `citadel` database (ADR-0006).
//!
//! One append-only corpus, one production migrator. Services never
//! self-migrate at startup; the `citadel-migrate` binary is the only
//! production component that applies schema changes, and database-backed
//! tests initialize through the same [`migrate`] entry point so production
//! and test schema construction cannot drift.
//!
//! Safety posture (ADR-0006 §1):
//! - `ignore_missing` stays at its default **false** and default sqlx
//!   locking is kept — a partial view of the shared history is exactly the
//!   failure this ADR removes.
//! - [`migrate`] pins `search_path` to `pg_catalog, public, pg_temp` and
//!   fully qualifies `public._sqlx_migrations`; a migration history table in
//!   ANY other schema is a fatal configuration error, never an independent
//!   service history.
//! - Before any new SQL, the exact-prefix preflight compares successful
//!   applied rows against the embedded corpus by version AND SHA-384
//!   checksum. This is ADDITIONAL to sqlx's own VersionMissing /
//!   VersionMismatch / dirty-state / locking behavior — sqlx's checks are
//!   not bypassed, they are preceded.
//! - Bounds: 60s lock acquisition (`lock_timeout`), 300s per statement
//!   (`statement_timeout`), plus a tokio backstop over the whole run. A
//!   timeout is fatal; a second runner behind a held lock fails closed
//!   instead of hanging.

use serde::Deserialize;
use sqlx::migrate::Migrator;
use sqlx::{PgConnection, PgPool, Row};
use std::time::Duration;
use thiserror::Error;

/// ADR-0006 §1 bound: migration lock acquisition. A held advisory lock must
/// make a second runner fail closed within about this long, never hang.
pub const LOCK_TIMEOUT_SECS: u64 = 60;
/// ADR-0006 §1 bound: per-migration (per-statement) execution.
pub const MIGRATION_STATEMENT_TIMEOUT_SECS: u64 = 300;
/// ADR-0006 §1: the canonical history lives in `public`, with the temporary
/// schema searched last.
const SEARCH_PATH: &str = "pg_catalog, public, pg_temp";

/// The embedded canonical corpus. `sqlx::migrate!` embeds the WORKING-TREE
/// bytes at compile time, so `.gitattributes` pins these files to LF — a
/// CRLF checkout would silently change the embedded checksums.
///
/// Defaults are load-bearing: `ignore_missing = false`, locking on.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Error)]
pub enum MigrateError {
    /// Exact-prefix preflight failed: unknown/missing/non-prefix applied
    /// version, checksum drift, a dirty row, or a history table in another
    /// schema. No new SQL was executed.
    #[error("migration preflight failed: {0}")]
    Preflight(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("sqlx migrator error: {0}")]
    Sqlx(#[from] sqlx::migrate::MigrateError),
    /// The tokio backstop over the whole run fired. The statement-level
    /// bounds (lock_timeout/statement_timeout) should fire first; this is
    /// fail-closed defense in depth.
    #[error("migration run exceeded its overall bound of {0:?} (ADR-0006 §1)")]
    Timeout(Duration),
}

/// The single entry point for applying the canonical corpus: used by the
/// `citadel-migrate` binary AND by every database-backed test (ADR-0006 §1).
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    migrate_with_bounds(pool, LOCK_TIMEOUT_SECS, MIGRATION_STATEMENT_TIMEOUT_SECS).await
}

/// [`migrate`] with explicit bounds. The 60s/300s defaults are pinned by
/// ADR-0006 §1; this seam exists so the lock-timeout evidence test can
/// prove fail-closed behavior in seconds instead of a minute.
pub async fn migrate_with_bounds(
    pool: &PgPool,
    lock_timeout_secs: u64,
    statement_timeout_secs: u64,
) -> Result<(), MigrateError> {
    // One connection for everything: the session settings below must cover
    // the preflight AND the migrator's own lock/statements.
    let mut conn = pool.acquire().await?;
    sqlx::query(&format!("SET search_path TO {SEARCH_PATH}"))
        .execute(&mut *conn)
        .await?;
    // SET does not take bind parameters; both values are u64s we control.
    sqlx::query(&format!("SET lock_timeout = '{lock_timeout_secs}s'"))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!(
        "SET statement_timeout = '{statement_timeout_secs}s'"
    ))
    .execute(&mut *conn)
    .await?;

    preflight(&mut conn).await?;

    // Backstop over the whole run: lock bound + per-migration bounds +
    // margin. The statement-level settings are the primary mechanism.
    // `run_direct` is sqlx's sanctioned path for a single already-acquired
    // connection (`run` hits the Acquire "not general enough" limitation);
    // it keeps the SAME connection, so the session settings above cover the
    // migrator's lock and statements.
    let n_migrations = MIGRATOR.migrations.len() as u64;
    let overall =
        Duration::from_secs(lock_timeout_secs + statement_timeout_secs * n_migrations + 60);
    tokio::time::timeout(overall, MIGRATOR.run_direct(&mut *conn))
        .await
        .map_err(|_| MigrateError::Timeout(overall))??;
    Ok(())
}

/// One applied row of `public._sqlx_migrations`, as the preflight reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRow {
    pub version: i64,
    pub checksum: Vec<u8>,
    pub success: bool,
}

/// The exact-prefix preflight (ADR-0006 §1), additional to sqlx's own
/// validation. Runs on the migration connection before any new SQL.
async fn preflight(conn: &mut PgConnection) -> Result<(), MigrateError> {
    // A migration history in any schema other than `public` is a fatal
    // configuration error — never an independent service history.
    let foreign: Vec<String> = sqlx::query(
        "SELECT n.nspname AS schema_name \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relname = '_sqlx_migrations' AND c.relkind IN ('r', 'p') \
           AND n.nspname <> 'public' \
         ORDER BY n.nspname",
    )
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| r.get("schema_name"))
    .collect();
    if !foreign.is_empty() {
        return Err(MigrateError::Preflight(format!(
            "found _sqlx_migrations outside the public schema ({}); \
             ADR-0006 §1 makes a second migration history fatal",
            foreign.join(", ")
        )));
    }

    let exists: bool =
        sqlx::query("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL AS e")
            .fetch_one(&mut *conn)
            .await?
            .get("e");
    if !exists {
        // Fresh database: empty history is a prefix of every corpus.
        return Ok(());
    }

    let applied: Vec<AppliedRow> = sqlx::query(
        "SELECT version, checksum, success FROM public._sqlx_migrations ORDER BY version ASC",
    )
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| AppliedRow {
        version: r.get("version"),
        checksum: r.get("checksum"),
        success: r.get("success"),
    })
    .collect();

    check_prefix(&applied, &MIGRATOR.migrations).map_err(MigrateError::Preflight)
}

/// Pure prefix comparison, unit-tested directly: `applied` (ordered by
/// version) must exactly match a prefix of `corpus` by version AND SHA-384
/// checksum. Any dirty row, unknown version, hole, drift, or history longer
/// than the corpus is fatal.
fn check_prefix(applied: &[AppliedRow], corpus: &[sqlx::migrate::Migration]) -> Result<(), String> {
    if let Some(dirty) = applied.iter().find(|r| !r.success) {
        return Err(format!(
            "migration {:04} is recorded as failed (dirty); the database needs \
             manual recovery before any new SQL runs",
            dirty.version
        ));
    }
    if applied.len() > corpus.len() {
        return Err(format!(
            "{} applied rows exceed the embedded corpus of {} migrations; an older \
             migration artifact must never reinterpret or remove newer history (ADR-0006 §3)",
            applied.len(),
            corpus.len()
        ));
    }
    for (i, row) in applied.iter().enumerate() {
        let expected = &corpus[i];
        if row.version != expected.version {
            return Err(format!(
                "applied version {:04} at position {} does not match corpus version {:04}: \
                 the applied history is not an exact prefix of the canonical corpus \
                 (unknown, missing, or reordered migration)",
                row.version,
                i + 1,
                expected.version
            ));
        }
        if row.checksum.as_slice() != expected.checksum.as_ref() {
            return Err(format!(
                "checksum drift on migration {:04}: the recorded SHA-384 does not match \
                 the canonical file; history must be immutable (ADR-0006 §2)",
                row.version
            ));
        }
    }
    Ok(())
}

// ---------- Migration manifest (ADR-0006 §2) ----------

const MANIFEST_JSON: &str = include_str!("../manifest.json");

/// One manifest entry. The manifest records review responsibility and risk
/// classification; it does not split execution history.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ManifestEntry {
    pub version: i64,
    pub filename: String,
    /// SQLx SHA-384 checksum of the file bytes, hex.
    pub sha384: String,
    pub responsible_service: String,
    /// Transaction mode (`tx` for every current migration).
    pub tx: String,
    /// expand | contract | data (recorded in CORE; fail-closed enforcement
    /// is a later phase of ADR-0006).
    pub risk: String,
    pub recovery: String,
    /// The ACCEPTED ADR governing the schema decision.
    pub adr: String,
}

/// The embedded append-only manifest. Panics only if the committed file is
/// not valid JSON — the unit tests and ci/check_migrations.py pin the shape.
pub fn manifest() -> Vec<ManifestEntry> {
    serde_json::from_str(MANIFEST_JSON).expect("embedded manifest.json must be valid")
}

#[cfg(test)]
fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex string must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("manifest sha384 must be hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adr_bounds_are_the_pinned_values() {
        assert_eq!(LOCK_TIMEOUT_SECS, 60, "ADR-0006 §1 lock bound");
        assert_eq!(
            MIGRATION_STATEMENT_TIMEOUT_SECS, 300,
            "ADR-0006 §1 execution bound"
        );
    }

    #[test]
    fn manifest_is_well_formed_and_strictly_appending() {
        let entries = manifest();
        assert!(!entries.is_empty());
        for w in entries.windows(2) {
            assert!(
                w[0].version < w[1].version,
                "versions must strictly increase"
            );
        }
        for e in &entries {
            assert!(e.version > 0);
            assert!(e.filename.ends_with(".sql"));
            assert_eq!(e.sha384.len(), 96, "SHA-384 hex is 96 chars");
            assert!(!e.responsible_service.is_empty());
            assert!(!e.tx.is_empty());
            assert!(["expand", "contract", "data"].contains(&e.risk.as_str()));
            assert!(!e.recovery.is_empty());
            assert!(!e.adr.is_empty());
        }
    }

    /// The manifest must describe EXACTLY the embedded corpus: same versions,
    /// same filenames, same SHA-384 checksums as sqlx computes at compile time.
    #[test]
    fn manifest_matches_embedded_corpus() {
        let entries = manifest();
        let corpus = &MIGRATOR.migrations;
        assert_eq!(entries.len(), corpus.len());
        for (entry, migration) in entries.iter().zip(corpus.iter()) {
            assert_eq!(entry.version, migration.version);
            assert_eq!(
                entry.filename,
                // sqlx derives the description from the filename: version
                // prefix and .sql stripped, underscores rendered as spaces.
                format!(
                    "{:04}_{}.sql",
                    migration.version,
                    migration.description.replace(' ', "_")
                ),
                "manifest filename must match the embedded migration description"
            );
            assert_eq!(
                hex_decode(&entry.sha384),
                migration.checksum.as_ref(),
                "manifest sha384 must equal the sqlx checksum of {:04}",
                entry.version
            );
        }
    }

    fn row(version: i64, corpus: &[sqlx::migrate::Migration], success: bool) -> AppliedRow {
        let checksum = corpus
            .iter()
            .find(|m| m.version == version)
            .map(|m| m.checksum.as_ref().to_vec())
            .unwrap_or_else(|| vec![0u8; 48]);
        AppliedRow {
            version,
            checksum,
            success,
        }
    }

    #[test]
    fn check_prefix_accepts_empty_and_exact_prefixes() {
        let corpus = &MIGRATOR.migrations;
        assert!(check_prefix(&[], corpus).is_ok());
        let one = vec![row(1, corpus, true)];
        assert!(check_prefix(&one, corpus).is_ok());
        let full: Vec<_> = corpus
            .iter()
            .map(|m| row(m.version, corpus, true))
            .collect();
        assert!(check_prefix(&full, corpus).is_ok());
    }

    #[test]
    fn check_prefix_rejects_dirty_row() {
        let corpus = &MIGRATOR.migrations;
        let applied = vec![row(1, corpus, false)];
        let err = check_prefix(&applied, corpus).unwrap_err();
        assert!(err.contains("failed"), "{err}");
    }

    #[test]
    fn check_prefix_rejects_unknown_version() {
        let corpus = &MIGRATOR.migrations;
        let mut applied: Vec<_> = corpus
            .iter()
            .map(|m| row(m.version, corpus, true))
            .collect();
        applied.push(row(999, corpus, true));
        let err = check_prefix(&applied, corpus).unwrap_err();
        assert!(err.contains("exceed the embedded corpus"), "{err}");
    }

    #[test]
    fn check_prefix_rejects_missing_and_reordered_versions() {
        let corpus = &MIGRATOR.migrations;
        // 0001 + 0003 without 0002: a hole is not a prefix.
        let hole = vec![row(1, corpus, true), row(3, corpus, true)];
        assert!(check_prefix(&hole, corpus).is_err());
        // 0002 first: history that does not start at the corpus head.
        let reordered = vec![row(2, corpus, true)];
        assert!(check_prefix(&reordered, corpus).is_err());
    }

    #[test]
    fn check_prefix_rejects_checksum_drift() {
        let corpus = &MIGRATOR.migrations;
        let mut drifted = row(1, corpus, true);
        drifted.checksum[0] ^= 0xFF;
        let err = check_prefix(&[drifted], corpus).unwrap_err();
        assert!(err.contains("checksum drift"), "{err}");
    }
}
