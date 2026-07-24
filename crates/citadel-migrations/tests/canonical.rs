//! ADR-0006 CORE evidence: the canonical migration runner against REAL
//! PostgreSQL 16 (PLAN.md §13 — never a mock; `#[ignore]` + DATABASE_URL,
//! the CI db-tests job provisions postgres:16).
//!
//! Isolation: these tests manipulate `_sqlx_migrations` directly, so each
//! case runs in a THROWAWAY DATABASE created for it and dropped on
//! teardown — never a shared history, never TRUNCATE of anything. The
//! preflight under test pins search_path to `public, pg_temp`
//! (ADR-0006 §1, Amendment 1), so per-test schemas are not an option;
//! databases are.

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

/// ADR-0006 Amendment 1 evidence: from an EMPTY database, the canonical
/// runner's unqualified `_sqlx_migrations` creation lands in `public` (the
/// first explicitly named schema of `public, pg_temp`), and the effective
/// RELATION and TYPE lookup order is `pg_catalog` (implicit, unnamed),
/// then `public`, then the temporary schema (named last).
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migrations_create_public_history_with_catalog_and_temp_precedence() {
    let db = TestDb::create().await;
    // One dedicated connection: search_path is session state, so the
    // lookup probes pin the amendment's path on the connection they run on.
    let pool = db.pool(1).await;

    citadel_migrations::migrate(&pool)
        .await
        .expect("apply from empty");

    // The history exists ONLY at public._sqlx_migrations: sqlx created it
    // unqualified, so its home proves the creation target. Any other schema
    // here is the run-29983887580 failure mode (pg_catalog) or a second
    // history (fatal per ADR-0006 §1).
    let homes: Vec<String> = sqlx::query(
        "SELECT n.nspname AS s \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relname = '_sqlx_migrations' AND c.relkind IN ('r', 'p') \
         ORDER BY n.nspname",
    )
    .fetch_all(&pool)
    .await
    .expect("locate history table")
    .iter()
    .map(|r| r.get("s"))
    .collect();
    assert_eq!(homes, ["public"], "history must live only in public");

    // Pin the Amendment-1 path explicitly: the probes must not depend on
    // pool reuse of the migrator's session state.
    sqlx::query("SET search_path TO public, pg_temp")
        .execute(&pool)
        .await
        .unwrap();
    // Unqualified lookup of the history resolves to the public table.
    let history: bool = sqlx::query_scalar(
        "SELECT to_regclass('_sqlx_migrations') = 'public._sqlx_migrations'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(history, "unqualified history must resolve in public");

    // Initialize the temporary schema and prove it is live.
    sqlx::query("CREATE TEMP TABLE precedence_rel (x int)")
        .execute(&pool)
        .await
        .unwrap();
    let temp_live: bool = sqlx::query_scalar("SELECT pg_my_temp_schema() <> 0")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(temp_live, "temporary schema must be initialized");

    let resolves_to = |name: &str, qualified: &str| {
        let pool = pool.clone();
        let name = name.to_string();
        let qualified = qualified.to_string();
        async move {
            sqlx::query_scalar::<_, bool>(&format!(
                "SELECT to_regclass('{name}') = '{qualified}'::regclass"
            ))
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let type_resolves_to = |name: &str, qualified: &str| {
        let pool = pool.clone();
        let name = name.to_string();
        let qualified = qualified.to_string();
        async move {
            sqlx::query_scalar::<_, bool>(&format!(
                "SELECT '{name}'::regtype = '{qualified}'::regtype"
            ))
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    // RELATION order, all three pairwise edges of
    // pg_catalog -> public -> pg_temp:
    // public beats pg_temp: same table in both, public wins.
    sqlx::query("CREATE TABLE public.precedence_rel (x int)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        resolves_to("precedence_rel", "public.precedence_rel").await,
        "public must precede the temporary schema for relations"
    );
    // pg_catalog beats public: a public table named like a catalog relation
    // must NOT shadow the built-in (the rejected `public, pg_catalog, ...`
    // ordering would allow exactly this).
    sqlx::query("CREATE TABLE public.pg_am (x int)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        resolves_to("pg_am", "pg_catalog.pg_am").await,
        "pg_catalog must precede public for relations"
    );
    // pg_catalog beats pg_temp: temp named LAST means a temp table named
    // like a catalog relation must not shadow it either.
    sqlx::query("CREATE TEMP TABLE pg_proc (x int)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        resolves_to("pg_proc", "pg_catalog.pg_proc").await,
        "pg_catalog must precede the temporary schema for relations"
    );

    // TYPE order, same three edges:
    sqlx::query("CREATE TYPE public.precedence_ty AS ENUM ('a')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TYPE pg_temp.precedence_ty AS ENUM ('a')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        type_resolves_to("precedence_ty", "public.precedence_ty").await,
        "public must precede the temporary schema for types"
    );
    sqlx::query("CREATE TYPE public.int4 AS ENUM ('a')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        type_resolves_to("int4", "pg_catalog.int4").await,
        "pg_catalog must precede public for types"
    );
    sqlx::query("CREATE TYPE pg_temp.text AS ENUM ('a')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        type_resolves_to("text", "pg_catalog.text").await,
        "pg_catalog must precede the temporary schema for types"
    );

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

/// ADR-0006 §1 evidence: the exact-prefix preflight runs UNDER the
/// migration lock. With the lock held and history planted that preflight
/// MUST reject, a second runner fails on the lock wait — it never reaches
/// preflight. Only after the lock is released does the same runner reach
/// preflight and reject the planted history. A preflight that ran outside
/// the lock would return MigrateError::Preflight in the first phase.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migration_preflight_runs_under_migration_lock() {
    let db = TestDb::create().await;
    let pool = db.pool(2).await;
    citadel_migrations::migrate(&pool).await.expect("apply");

    // Plant history the preflight must reject (unknown version 999 — an
    // applied row beyond the corpus head).
    sqlx::query(
        "INSERT INTO public._sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES (999, 'bogus', true, decode($1, 'hex'), 0)",
    )
    .bind("00".repeat(48))
    .execute(&pool)
    .await
    .expect("plant unknown version");

    // Hold the migrator's advisory lock on a dedicated connection (the
    // test-side CRC reimplementation is the independent oracle for the id
    // the library now derives for itself).
    let lock_id = sqlx_migration_lock_id(&db.name);
    let holder = db.pool(1).await;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(&holder)
        .await
        .expect("take advisory lock");
    assert!(got, "test must hold the migrator lock");

    // Phase 1: the second runner must die on the LOCK, not on preflight.
    let err = citadel_migrations::migrate_with_bounds(&pool, 2, 300)
        .await
        .expect_err("a held lock must stop the runner before preflight");
    assert!(
        !matches!(err, citadel_migrations::MigrateError::Preflight(_)),
        "preflight ran WITHOUT the lock (TOCTOU): {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("lock") || msg.contains("timeout") || msg.contains("canceling"),
        "phase 1 error should name the lock wait: {msg}"
    );

    // Phase 2: release the lock; the same runner must now reach preflight
    // and reject the planted history — the check still happens, under the
    // lock.
    let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .fetch_one(&holder)
        .await
        .expect("release advisory lock");
    assert!(released);
    let err = citadel_migrations::migrate_with_bounds(&pool, 2, 300)
        .await
        .expect_err("planted history must be fatal once the lock is held");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Preflight(_)),
        "expected preflight failure after lock release, got {err:?}"
    );

    drop(holder);
    drop(pool);
    db.teardown().await;
}

// ---------- Exit-path cleanup evidence (Sol re-review of #39) ----------
//
// sqlx-core 0.8.6 run_direct takes its advisory lock at entry but unlocks
// only on the success path; every `?` in between (Dirty, VersionMismatch,
// ensure_migrations_table, a failing migration) returns with that
// acquisition still held. A dropped PoolConnection returns to the pool
// WITHOUT a session reset (pool/connection.rs return_to_pool), so the
// leaked hold — and the runner's SET search_path/lock_timeout/
// statement_timeout — would persist on the pooled connection. The runner
// now releases unconditionally on the way out (pg_advisory_unlock_all +
// RESET), and closes the connection instead on the tokio backstop. These
// tests are the evidence; each one fails against the pre-fix runner.

/// Advisory locks held by ANY backend of the current (throwaway) database.
async fn advisory_locks_held(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks \
         WHERE locktype = 'advisory' \
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_one(pool)
    .await
    .expect("count advisory locks")
}

/// (search_path, lock_timeout, statement_timeout) as one session sees them.
async fn session_settings(pool: &PgPool) -> (String, String, String) {
    let sp: String = sqlx::query_scalar("SHOW search_path")
        .fetch_one(pool)
        .await
        .unwrap();
    let lt: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(pool)
        .await
        .unwrap();
    let st: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(pool)
        .await
        .unwrap();
    (sp, lt, st)
}

/// ERROR PATH: a failing migration (run_direct error under the lock) must
/// leave no advisory hold and no session settings behind, and a follow-up
/// runner on a DIFFERENT pooled connection must succeed rather than block
/// to lock_timeout.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migration_error_path_releases_lock_and_settings() {
    let db = TestDb::create().await;
    // A pristine session, only to read the server's default settings.
    let fresh = db.pool(1).await;
    let defaults = session_settings(&fresh).await;

    let pool = db.pool(2).await;
    // Sabotage: 0001 CREATE TABLE accounts fails mid-run — AFTER sqlx's
    // run_direct took its advisory hold — so the exercised error path is
    // run_direct's, not the preflight's.
    sqlx::query("CREATE TABLE public.accounts (id UUID PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();

    let err = citadel_migrations::migrate_with_bounds(&pool, 2, 300)
        .await
        .expect_err("a conflicting table must fail the run");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Sqlx(_)),
        "expected a run_direct (sqlx) failure, got {err:?}"
    );

    // Direct leak evidence: zero advisory holds survive in this database.
    // (Pre-fix: sqlx's unleashed run_direct hold persists here.)
    assert_eq!(
        advisory_locks_held(&fresh).await,
        0,
        "an advisory lock leaked onto the failed session"
    );

    // The failed session is back in the pool; pin it out and prove it
    // carries none of the migration session settings.
    let mut pinned = pool.acquire().await.expect("pin the failed session");
    let sp: String = sqlx::query_scalar("SHOW search_path")
        .fetch_one(&mut *pinned)
        .await
        .unwrap();
    let lt: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&mut *pinned)
        .await
        .unwrap();
    let st: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *pinned)
        .await
        .unwrap();
    assert_eq!(
        (sp, lt, st),
        defaults,
        "session settings leaked onto the pooled connection"
    );

    // Functional evidence: with the failed connection pinned out of the
    // pool, the follow-up runner MUST land on a different pooled
    // connection. A leaked hold on the failed session would block this run
    // to lock_timeout (the exact pre-fix failure shape, silently and only
    // sometimes); here it must simply succeed.
    sqlx::query("DROP TABLE public.accounts")
        .execute(&fresh)
        .await
        .unwrap();
    citadel_migrations::migrate_with_bounds(&pool, 5, 300)
        .await
        .expect("migrate on a different pooled connection must not block on a leaked lock");
    assert_eq!(history_versions(&fresh).await, CORPUS_HEAD);

    drop(pinned);
    drop(pool);
    drop(fresh);
    db.teardown().await;
}

/// CANCELLATION PATH: the tokio backstop drops run_direct mid-flight; the
/// runner must not return the poisoned connection to the pool, and no
/// advisory hold may survive once the cancelled backend is gone.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migration_backstop_cancellation_releases_lock() {
    let db = TestDb::create().await;

    // Pre-0004 state (schema + history 0001–0003) so one migration is
    // pending when the cancelled run starts.
    let setup = db.pool(2).await;
    sqlx::raw_sql(include_str!("fixtures/pre_0004.sql"))
        .execute(&setup)
        .await
        .expect("apply pre-0004 fixture");
    assert_eq!(history_versions(&setup).await, [1, 2, 3]);

    // A second session holds SHARE on the history table: the preflight's
    // ACCESS SHARE reads pass, but run_direct's INSERT of the 0004 history
    // row (ROW EXCLUSIVE) blocks — inside the apply, under sqlx's advisory
    // hold, with no lock-wait error because lock_timeout is set high. Only
    // the tokio backstop can end this run.
    let blocker = db.pool(1).await;
    let mut btx = blocker.begin().await.unwrap();
    sqlx::query("LOCK TABLE public._sqlx_migrations IN SHARE MODE")
        .execute(&mut *btx)
        .await
        .unwrap();

    let pool = db.pool(2).await;
    let err = citadel_migrations::migrate_with_backstop(
        &pool,
        30,
        300,
        std::time::Duration::from_secs(2),
    )
    .await
    .expect_err("the backstop must cancel the blocked run");
    assert!(
        matches!(err, citadel_migrations::MigrateError::Timeout(_)),
        "expected the tokio backstop, got {err:?}"
    );

    // Free the blocked INSERT; the cancelled backend can now notice its
    // dead client and exit, releasing everything the session held.
    drop(btx);
    drop(blocker);

    // The backend may take a moment to die; poll for the lock to go.
    let mut released = false;
    for _ in 0..40 {
        if advisory_locks_held(&setup).await == 0 {
            released = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(
        released,
        "the cancelled run's advisory lock survived its backend"
    );

    // A subsequent runner succeeds: 0004 rolls forward and lands at head.
    citadel_migrations::migrate_with_bounds(&pool, 10, 300)
        .await
        .expect("migrate after a cancelled run must not block on a leaked lock");
    assert_eq!(history_versions(&setup).await, CORPUS_HEAD);

    drop(pool);
    drop(setup);
    db.teardown().await;
}

/// SUCCESS PATH (companion defect): even a clean run pinned search_path,
/// lock_timeout and statement_timeout on the session; those SETs must not
/// survive the call onto the pooled connection.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn canonical_migration_success_leaves_no_session_state() {
    let db = TestDb::create().await;
    let fresh = db.pool(1).await;
    let defaults = session_settings(&fresh).await;

    // One connection: the migrator's session is exactly the one the SHOWs
    // below interrogate. (Pre-fix: all three SETs leak here, and the two
    // looser timeouts would mask hangs in unrelated reusing queries.)
    let pool = db.pool(1).await;
    citadel_migrations::migrate(&pool).await.expect("apply");

    assert_eq!(
        session_settings(&pool).await,
        defaults,
        "the migration session settings survived the call"
    );
    assert_eq!(
        advisory_locks_held(&pool).await,
        0,
        "an advisory lock survived a successful run"
    );

    drop(pool);
    drop(fresh);
    db.teardown().await;
}
