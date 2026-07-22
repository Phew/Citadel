//! ADR-0006 CORE evidence: the canonical migration runner against REAL
//! PostgreSQL 16 (PLAN.md §13 — never a mock; `#[ignore]` + DATABASE_URL,
//! the CI db-tests job provisions postgres:16).
//!
//! Isolation: these tests manipulate `_sqlx_migrations` directly, so each
//! case runs in a THROWAWAY DATABASE created for it and dropped on
//! teardown — never a shared history, never TRUNCATE of anything. The
//! preflight under test pins search_path to `pg_catalog, public, pg_temp`
//! (ADR-0006 §1), so per-test schemas are not an option; databases are.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the canonical migration tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// A throwaway database for one test case (dropped on teardown; a panicked
/// test leaks it — CI's postgres is ephemeral per job, names are unique).
struct TestDb {
    name: String,
    admin: PgPool,
}

impl TestDb {
    async fn create() -> TestDb {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db_url())
            .await
            .expect("connect to real PostgreSQL (CI provisions it)");
        let name = format!("citadel_mig_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .expect("create per-test database");
        TestDb { name, admin }
    }

    fn url(&self) -> String {
        let base = db_url()
            .rsplit_once('/')
            .map(|(b, _)| b.to_string())
            .expect("DATABASE_URL must end in a database name");
        format!("{base}/{}", self.name)
    }

    async fn pool(&self, max: u32) -> PgPool {
        PgPoolOptions::new()
            .max_connections(max)
            .connect(&self.url())
            .await
            .expect("connect to per-test database")
    }

    async fn teardown(self) {
        // WITH (FORCE) disconnects stragglers (PG13+).
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            self.name
        ))
        .execute(&self.admin)
        .await
        .expect("drop test database");
    }
}

/// The canonical SHA-384 (hex) for a corpus version, from the embedded
/// manifest — the tests never hardcode checksums.
fn sha384_of(version: i64) -> String {
    citadel_migrations::manifest()
        .into_iter()
        .find(|e| e.version == version)
        .unwrap_or_else(|| panic!("manifest has version {version}"))
        .sha384
}

const HISTORY_DDL: &str = "CREATE TABLE public._sqlx_migrations (\
     version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
     installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, \
     checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL)";

async fn insert_history_row(pool: &PgPool, version: i64, success: bool) {
    sqlx::query(
        "INSERT INTO public._sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES ($1, 'test fixture', $2, decode($3, 'hex'), 0)",
    )
    .bind(version)
    .bind(success)
    .bind(sha384_of(version))
    .execute(pool)
    .await
    .expect("insert history row");
}

async fn history_versions(pool: &PgPool) -> Vec<i64> {
    sqlx::query("SELECT version FROM public._sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("read history")
        .iter()
        .map(|r| r.get("version"))
        .collect()
}

async fn public_tables(pool: &PgPool) -> Vec<String> {
    sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .expect("list tables")
    .iter()
    .map(|r| r.get("table_name"))
    .collect()
}

/// Catalog shape of the public schema (table.column:type, ordered) — the
/// regression comparison for the upgrade fixture. This is a catalog
/// comparison, not a semantic-compatibility proof (ADR-0006 §4).
async fn catalog_shape(pool: &PgPool) -> Vec<String> {
    sqlx::query(
        "SELECT table_name || '.' || column_name || ':' || data_type AS shape \
         FROM information_schema.columns WHERE table_schema = 'public' \
         ORDER BY table_name, column_name",
    )
    .fetch_all(pool)
    .await
    .expect("catalog shape")
    .iter()
    .map(|r| r.get("shape"))
    .collect()
}

const CORPUS_HEAD: [i64; 4] = [1, 2, 3, 4];

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_apply_from_empty_postgres() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    citadel_migrations::migrate(&pool)
        .await
        .expect("apply from empty");
    assert_eq!(history_versions(&pool).await, CORPUS_HEAD);

    let tables = public_tables(&pool).await;
    for expected in [
        "accounts",
        "devices",
        "key_packages",
        "auth_challenges",
        "auth_tokens",
        "kt_leaves",
        "kt_sth",
        "groups",
        "group_messages",
        "welcome_deliveries",
        "_sqlx_migrations",
    ] {
        assert!(tables.contains(&expected.to_string()), "missing {expected}");
    }

    // Every recorded migration succeeded; none is dirty.
    let dirty: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations WHERE NOT success")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dirty, 0);

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reapply_is_noop() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    citadel_migrations::migrate(&pool)
        .await
        .expect("first apply");
    let shape_before = catalog_shape(&pool).await;
    citadel_migrations::migrate(&pool)
        .await
        .expect("reapply must be a no-op");
    assert_eq!(history_versions(&pool).await, CORPUS_HEAD);
    assert_eq!(catalog_shape(&pool).await, shape_before);

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_upgrade_previous_schema_fixture() {
    // The pre-0004 state: schema 0001-0003 + their history rows.
    let upgraded = TestDb::create().await;
    let upgraded_pool = upgraded.pool(2).await;
    sqlx::raw_sql(include_str!("fixtures/pre_0004.sql"))
        .execute(&upgraded_pool)
        .await
        .expect("apply pre-0004 fixture");
    assert_eq!(history_versions(&upgraded_pool).await, [1, 2, 3]);

    // The canonical runner takes it to head.
    citadel_migrations::migrate(&upgraded_pool)
        .await
        .expect("upgrade to head");
    assert_eq!(history_versions(&upgraded_pool).await, CORPUS_HEAD);

    // Catalog comparison against a from-empty apply (regression evidence,
    // not a semantic-compatibility claim, ADR-0006 §4).
    let fresh = TestDb::create().await;
    let fresh_pool = fresh.pool(2).await;
    citadel_migrations::migrate(&fresh_pool)
        .await
        .expect("apply from empty");
    assert_eq!(
        catalog_shape(&upgraded_pool).await,
        catalog_shape(&fresh_pool).await,
        "upgraded schema must match a from-empty apply"
    );

    drop(upgraded_pool);
    drop(fresh_pool);
    upgraded.teardown().await;
    fresh.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reject_unknown_applied_version() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    citadel_migrations::migrate(&pool).await.expect("apply");
    // A bogus row BEYOND the corpus head: an older artifact must never
    // reinterpret or remove newer history (ADR-0006 §3).
    sqlx::query(
        "INSERT INTO public._sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES (999, 'bogus', true, decode($1, 'hex'), 0)",
    )
    .bind("00".repeat(48))
    .execute(&pool)
    .await
    .expect("plant unknown version");

    let err = citadel_migrations::migrate(&pool)
        .await
        .expect_err("unknown applied version must be fatal");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Preflight(_)),
        "expected preflight failure, got {err:?}"
    );
    // No new SQL ran: history is untouched.
    assert_eq!(history_versions(&pool).await, [1, 2, 3, 4, 999]);

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reject_missing_applied_version() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    // Hand-built history 0001 + 0003 (correct checksums, 0002 missing): a
    // hole is not a prefix.
    sqlx::query(HISTORY_DDL).execute(&pool).await.unwrap();
    insert_history_row(&pool, 1, true).await;
    insert_history_row(&pool, 3, true).await;

    let err = citadel_migrations::migrate(&pool)
        .await
        .expect_err("a hole in the applied history must be fatal");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Preflight(_)),
        "expected preflight failure, got {err:?}"
    );
    assert_eq!(history_versions(&pool).await, [1, 3]);

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reject_checksum_drift() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    citadel_migrations::migrate(&pool).await.expect("apply");
    // Flip one recorded checksum byte: history must be immutable.
    sqlx::query(
        "UPDATE public._sqlx_migrations \
         SET checksum = decode($1, 'hex') WHERE version = 2",
    )
    .bind(format!("ff{}", &sha384_of(2)[2..]))
    .execute(&pool)
    .await
    .expect("plant checksum drift");

    let err = citadel_migrations::migrate(&pool)
        .await
        .expect_err("checksum drift must be fatal");
    match err {
        citadel_migrations::MigrateError::Preflight(msg) => {
            assert!(msg.contains("checksum drift"), "{msg}");
        }
        other => panic!("expected preflight failure, got {other:?}"),
    }

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reject_non_prefix_history() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    // History that does not START at the corpus head (0002 + 0003, no
    // 0001): not a prefix even though every row is individually known.
    sqlx::query(HISTORY_DDL).execute(&pool).await.unwrap();
    insert_history_row(&pool, 2, true).await;
    insert_history_row(&pool, 3, true).await;

    let err = citadel_migrations::migrate(&pool)
        .await
        .expect_err("non-prefix history must be fatal");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Preflight(_)),
        "expected preflight failure, got {err:?}"
    );

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_reject_wrong_schema_history() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;

    // A second migration history in another schema is a fatal configuration
    // error, never an independent service history (ADR-0006 §1).
    sqlx::query("CREATE SCHEMA foo")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE foo._sqlx_migrations (version BIGINT PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();

    let err = citadel_migrations::migrate(&pool)
        .await
        .expect_err("a foreign _sqlx_migrations must be fatal");
    match err {
        citadel_migrations::MigrateError::Preflight(msg) => {
            assert!(msg.contains("outside the public schema"), "{msg}");
        }
        other => panic!("expected preflight failure, got {other:?}"),
    }

    drop(pool);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_concurrent_runners_serialize() {
    let db = TestDb::create().await;

    const RUNNERS: usize = 8;
    let mut tasks = Vec::new();
    for _ in 0..RUNNERS {
        let pool = db.pool(2).await;
        tasks.push(tokio::spawn(async move {
            citadel_migrations::migrate(&pool).await
        }));
    }
    for t in tasks {
        t.await
            .expect("runner panicked")
            .expect("every concurrent runner must succeed");
    }

    // One history, exactly at head, with the full schema.
    let pool = db.pool(2).await;
    assert_eq!(history_versions(&pool).await, CORPUS_HEAD);
    assert!(public_tables(&pool)
        .await
        .contains(&"group_messages".into()));

    drop(pool);
    db.teardown().await;
}

/// CRC-32 (ISO-HDLC), reimplemented here to derive the SAME advisory lock
/// id sqlx's migrator uses (0x3d32ad9e * CRC32(database name)) so the test
/// can hold that exact lock. Sanity-checked against the known vector.
fn crc32_iso_hdlc(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn sqlx_migration_lock_id(database_name: &str) -> i64 {
    0x3d32_ad9e_i64.wrapping_mul(crc32_iso_hdlc(database_name.as_bytes()) as i64)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migration_lock_timeout_fails_closed() {
    // The CRC reimplementation must match the standard vector, or the lock
    // id below proves nothing.
    assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);

    let db = TestDb::create().await;
    let pool = db.pool(2).await;
    citadel_migrations::migrate(&pool).await.expect("apply");

    // Hold the migrator's advisory lock on a dedicated connection.
    let lock_id = sqlx_migration_lock_id(&db.name);
    let holder = db.pool(1).await;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(&holder)
        .await
        .expect("take advisory lock");
    assert!(got, "test must hold the migrator lock");

    // A second runner with a 2s lock bound (the production default is the
    // pinned 60s — asserting THAT constant is the unit tests' job; here we
    // prove the fail-closed mechanism in seconds) must fail, not hang.
    let start = std::time::Instant::now();
    let err = citadel_migrations::migrate_with_bounds(&pool, 2, 300)
        .await
        .expect_err("a held migration lock must make the runner fail closed");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "runner must fail within about its lock bound, took {elapsed:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("lock") || msg.contains("timeout") || msg.contains("canceling"),
        "error should name the lock wait: {msg}"
    );

    drop(holder);
    drop(pool);
    db.teardown().await;
}
