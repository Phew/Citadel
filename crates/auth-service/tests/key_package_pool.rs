//! M1 acceptance property: a KeyPackage is consumed by exactly one caller,
//! ever, under concurrent load (PLAN.md §9 M1; FOR UPDATE SKIP LOCKED).
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.

use std::collections::HashSet;

use auth_service::store::{self, StoreError};
use citadel_proto::ids::{AccountId, DeviceId};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the pool property test; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate. These tests run in parallel against ONE database,
/// so isolation comes from fresh random account/device UUIDs per case —
/// never from TRUNCATE, which races the other tests mid-drain (the first
/// db-tests run, 2026-07-19, failed both hammer tests on exactly that
/// cross-test truncation).
async fn fresh_pool() -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(32)
        .connect(&db_url())
        .await
        .expect("connect to real PostgreSQL (CI provisions it)");
    citadel_migrations::migrate(&pool)
        .await
        .expect("apply canonical migrations (ADR-0006)");
    pool
}

async fn make_account(pool: &PgPool) -> AccountId {
    let id = AccountId::new();
    sqlx::query("INSERT INTO accounts (id, handle, identity_pubkey) VALUES ($1, $2, $3)")
        .bind(id.as_uuid())
        .bind(format!("user-{}", id.as_uuid().simple()))
        .bind(vec![0xAAu8; 32])
        .execute(pool)
        .await
        .expect("insert account");
    id
}

async fn make_device(pool: &PgPool, account: AccountId) -> DeviceId {
    let id = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices (id, account_id, device_pubkey, credential) VALUES ($1, $2, $3, $4)",
    )
    .bind(id.as_uuid())
    .bind(account.as_uuid())
    .bind(vec![0xBBu8; 32])
    .bind(vec![0xCCu8; 16])
    .execute(pool)
    .await
    .expect("insert device");
    id
}

/// `label` must differ per device under test: the cross-device assertions
/// compare package BYTES, so bytes must be globally unique (the first
/// db-tests run published identical per-device bytes and 30 correct
/// handouts read as 10 unique values + double consumption).
fn distinct_packages(label: &str, n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("{label}-keypackage-{i:05}").into_bytes())
        .collect()
}

/// Core exactly-once check: `consumers` racing tasks drain a pool of
/// `n_packages`; every package must come out exactly once.
async fn hammer(pool: &PgPool, n_packages: usize, consumers: usize) -> Result<(), String> {
    let account = make_account(pool).await;
    let device = make_device(pool, account).await;
    let published = distinct_packages("hammer", n_packages);
    let size = store::publish(pool, device, &published)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(size as usize, n_packages, "pool size after publish");

    let mut tasks = Vec::new();
    for _ in 0..consumers {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let mut mine = Vec::new();
            while let Some(pkg) = store::consume_one(&pool, device)
                .await
                .map_err(|e| e.to_string())?
            {
                mine.push(pkg.package_bytes);
            }
            Ok::<_, String>(mine)
        }));
    }

    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.map_err(|e| e.to_string())??);
    }

    let unique: HashSet<&Vec<u8>> = all.iter().collect();
    if unique.len() != all.len() {
        return Err(format!(
            "DOUBLE CONSUMPTION: {} packages handed out but only {} unique",
            all.len(),
            unique.len()
        ));
    }
    if all.len() != n_packages {
        return Err(format!(
            "published {n_packages} but {} were consumed",
            all.len()
        ));
    }
    let published_set: HashSet<&Vec<u8>> = published.iter().collect();
    if unique != published_set {
        return Err("consumed set differs from published set".into());
    }
    // And the pool must now be dry.
    let left = store::unconsumed_count(pool, device)
        .await
        .map_err(|e| e.to_string())?;
    if left != 0 {
        return Err(format!("{left} packages left after full drain"));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn exactly_once_deterministic_hammer() {
    let pool = fresh_pool().await;
    hammer(&pool, 64, 16)
        .await
        .expect("exactly-once under 16 racing consumers");
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn account_fetch_is_all_or_nothing() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let dev_a = make_device(&pool, account).await;
    let dev_b = make_device(&pool, account).await;

    // Only device A has stock: the fetch must fail AND burn nothing.
    store::publish(&pool, dev_a, &distinct_packages("dev-a", 1))
        .await
        .unwrap();
    let err = store::consume_for_account(&pool, account)
        .await
        .expect_err("fetch must fail when any device pool is empty");
    assert!(
        matches!(err, StoreError::PoolExhausted(d) if d == dev_b),
        "expected PoolExhausted(dev_b), got {err:?}"
    );
    assert_eq!(
        store::unconsumed_count(&pool, dev_a).await.unwrap(),
        1,
        "failed fetch must roll back device A's consumption"
    );

    // Stock both devices: the fetch now succeeds with exactly one each.
    store::publish(&pool, dev_b, &distinct_packages("dev-b", 2))
        .await
        .unwrap();
    let got = store::consume_for_account(&pool, account).await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(store::unconsumed_count(&pool, dev_a).await.unwrap(), 0);
    assert_eq!(store::unconsumed_count(&pool, dev_b).await.unwrap(), 1);
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn account_fetch_races_never_double_consume() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let devices: Vec<DeviceId> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(make_device(&pool, account).await);
        }
        v
    };
    for (i, d) in devices.iter().enumerate() {
        store::publish(&pool, *d, &distinct_packages(&format!("dev-{i}"), 10))
            .await
            .unwrap();
    }

    // 8 racers; exactly 10 account fetches can succeed (10 packages/device).
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let mut won = Vec::new();
            loop {
                match store::consume_for_account(&pool, account).await {
                    Ok(pkgs) => won.extend(pkgs.into_iter().map(|p| p.package_bytes)),
                    Err(StoreError::PoolExhausted(_)) => break,
                    Err(e) => panic!("unexpected store error: {e}"),
                }
            }
            won
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    assert_eq!(
        all.len(),
        30,
        "every published package consumed exactly once"
    );
    assert_eq!(
        all.iter().collect::<HashSet<_>>().len(),
        30,
        "no double consumption across account-level races"
    );
}

#[test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
fn exactly_once_proptest_random_load() {
    use proptest::test_runner::{Config, TestRunner};

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let pool = rt.block_on(fresh_pool());

    let mut runner = TestRunner::new(Config {
        cases: 8,
        ..Config::default()
    });
    let strategy = (1usize..=96, 2usize..=24);
    runner
        .run(&strategy, |(n_packages, consumers)| {
            rt.block_on(hammer(&pool, n_packages, consumers))
                .map_err(proptest::test_runner::TestCaseError::fail)?;
            Ok(())
        })
        .expect("exactly-once holds for randomized package/consumer counts");
}
