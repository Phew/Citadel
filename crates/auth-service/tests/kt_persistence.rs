//! ADR-0001 §4 / ADR-0003 §5 Evidence tests for KT persistence.
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.

use std::sync::{Arc, Mutex};

use auth_service::kt_store::{self, KtStoreError};
use auth_service::server::{self, AppState, KtState};
use auth_service::store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citadel_proto::credential::IdentityPublicKey;
use citadel_proto::error::ErrorResponse;
use citadel_proto::ids::AccountId;
use citadel_proto::kt::{ConsistencyProof, KtLeaf, KtProofResponse, SignedTreeHead};
use kt_log::{KtLog, TreeHeadSigner};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the KT persistence tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate in a per-test schema. The KT tables are GLOBALLY
/// sequenced (`kt_leaves.seq` is one BIGSERIAL per database) and the
/// leaf-index = seq - 1 guard (ADR-0001 §4) is exact only when the test
/// owns its sequence: parallel tests sharing one database and one sequence
/// would burn each other's seq values and trip the drift guard. Isolation
/// here is a fresh schema per case — the same philosophy as fresh random
/// UUIDs elsewhere, never TRUNCATE.
async fn fresh_pool() -> PgPool {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url())
        .await
        .expect("connect to real PostgreSQL (CI provisions it)");
    let schema = format!("t_{}", AccountId::new().as_uuid().simple());
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create per-test schema");

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO \"{schema}\""))
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&db_url())
        .await
        .expect("connect to real PostgreSQL (CI provisions it)");
    store::migrate(&pool).await.expect("apply migrations");
    pool
}

fn test_signer() -> TreeHeadSigner {
    TreeHeadSigner::from_seed(&[0xA5; 32])
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Distinct, deterministic leaves (fresh account ids keep parallel tests
/// isolated; the bytes differ per `n` so tampering is detectable).
fn make_leaf(n: u64) -> KtLeaf {
    KtLeaf {
        account_id: AccountId::new(),
        handle: format!("leaf-{n}"),
        identity_pubkey: IdentityPublicKey([n as u8; 32]),
        appended_at: 1_700_000_000 + n as i64,
    }
}

fn kt_state() -> Arc<KtState> {
    Arc::new(KtState {
        log: Mutex::new(KtLog::new()),
        signer: test_signer(),
    })
}

/// Append in memory and persist leaf+STH — the same order the registration
/// endpoint uses: in-memory index first, then the single DB transaction.
async fn append(pool: &PgPool, kt: &KtState, leaf: &KtLeaf) -> i64 {
    let (index, sth, leaf_bytes) = {
        let mut log = kt.log.lock().unwrap();
        let index = log.append(leaf);
        let sth = kt.signer.sign_head(&log, now_epoch());
        (index, sth, leaf.leaf_bytes())
    };
    kt_store::append_leaf_and_sth(pool, &leaf_bytes, index, &sth)
        .await
        .expect("append leaf and sth")
}

async fn get(app: Router2, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

type Router2 = axum::Router;

/// ADR-0001 §4: leaf index = seq - 1 (BIGSERIAL is 1-based, the RFC 6962
/// index is 0-based). Pinned here as the ADR requires.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn leaf_index_is_seq_minus_one() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    for (n, want_seq) in [(0, 1), (1, 2), (2, 3)] {
        let seq = append(&pool, &kt, &make_leaf(n)).await;
        assert_eq!(seq, want_seq, "leaf index {} maps to seq {}", n, want_seq);
    }
}

/// Startup happy path: the rebuilt log matches the latest persisted STH.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn startup_rebuilds_and_verifies() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    for n in 0..3 {
        append(&pool, &kt, &make_leaf(n)).await;
    }
    let rebuilt = kt_store::rebuild_and_verify(&pool)
        .await
        .expect("rebuild verifies");
    assert_eq!(rebuilt.size(), 3);
    let sth = kt_store::load_sth(&pool, None).await.unwrap().unwrap();
    assert_eq!(rebuilt.root(), sth.tbs.root_hash.0);
}

/// ADR-0001 Evidence (issue 004 F4): persist leaves + STH, corrupt a
/// `kt_leaves.leaf_bytes` row, assert the log refuses to start because the
/// rebuilt root ≠ persisted `kt_sth.root_hash`.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn startup_fails_on_tampered_leaf_bytes() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    for n in 0..3 {
        append(&pool, &kt, &make_leaf(n)).await;
    }

    sqlx::query("UPDATE kt_leaves SET leaf_bytes = $1 WHERE seq = 2")
        .bind(b"tampered-leaf-bytes".as_slice())
        .execute(&pool)
        .await
        .expect("corrupt a leaf row");

    match kt_store::rebuild_and_verify(&pool).await {
        Err(KtStoreError::RootMismatch {
            rebuilt_size,
            sth_size,
        }) => {
            assert_eq!(rebuilt_size, 3);
            assert_eq!(sth_size, 3);
        }
        other => panic!("expected RootMismatch, got {other:?}"),
    }
}

/// ADR-0003 Evidence: the proof endpoint returns the InclusionProof and
/// the exact SignedTreeHead it verifies against as one atomic response —
/// a mismatched pair is impossible by construction (kt-log's
/// `verify_inclusion` rejects a proof whose tree_size ≠ the head's).
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn kt_proof_response_pairs_proof_and_head() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    let leaves: Vec<KtLeaf> = (0..4).map(make_leaf).collect();
    for leaf in &leaves {
        append(&pool, &kt, leaf).await;
    }
    let app = server::router(AppState {
        pool: pool.clone(),
        kt: kt.clone(),
    });

    // Explicit tree_size: proof and head agree, and the pair verifies
    // client-side under the signer's public key.
    let (status, body) = get(app.clone(), "/v1/kt/proof?leaf=1&tree_size=3").await;
    assert_eq!(status, StatusCode::OK);
    let pair: KtProofResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pair.proof.leaf_index, 1);
    assert_eq!(pair.proof.tree_size, 3);
    assert_eq!(pair.signed_tree_head.tbs.tree_size, 3);
    assert!(kt_log::verify_tree_head(
        &pair.signed_tree_head,
        &test_signer().public_key()
    ));
    assert!(kt_log::verify_inclusion(
        &leaves[1],
        &pair.proof,
        &pair.signed_tree_head
    ));

    // Default tree_size is the latest STH.
    let (status, body) = get(app.clone(), "/v1/kt/proof?leaf=3").await;
    assert_eq!(status, StatusCode::OK);
    let pair: KtProofResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pair.proof.tree_size, 4);
    assert_eq!(pair.signed_tree_head.tbs.tree_size, 4);
    assert!(kt_log::verify_inclusion(
        &leaves[3],
        &pair.proof,
        &pair.signed_tree_head
    ));

    // Out-of-range leaf is a client error, not a 500.
    let (status, body) = get(app, "/v1/kt/proof?leaf=99&tree_size=4").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, citadel_proto::error::ErrorCode::InvalidRequest);
}

/// The remaining KT read surface: latest tree head and consistency proofs.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn kt_tree_head_and_consistency_endpoints() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    for n in 0..4 {
        append(&pool, &kt, &make_leaf(n)).await;
    }
    let app = server::router(AppState {
        pool: pool.clone(),
        kt: kt.clone(),
    });

    // Empty log elsewhere in the same database is not this test's concern:
    // this log has 4 leaves.
    let (status, body) = get(app.clone(), "/v1/kt/tree-head").await;
    assert_eq!(status, StatusCode::OK);
    let latest: SignedTreeHead = serde_json::from_slice(&body).unwrap();
    assert_eq!(latest.tbs.tree_size, 4);
    assert!(kt_log::verify_tree_head(
        &latest,
        &test_signer().public_key()
    ));

    let (status, body) = get(app.clone(), "/v1/kt/consistency?first=2&second=4").await;
    assert_eq!(status, StatusCode::OK);
    let proof: ConsistencyProof = serde_json::from_slice(&body).unwrap();
    let sth2 = kt_store::load_sth(&pool, Some(2)).await.unwrap().unwrap();
    assert!(kt_log::verify_consistency(&sth2, &latest, &proof));

    // Invalid ranges are client errors.
    let (status, _) = get(app.clone(), "/v1/kt/consistency?first=0&second=4").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(app, "/v1/kt/consistency?first=3&second=99").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// An STH that was never issued answers `not_found`, never a fabricated
/// head. (The parallel-test database is never empty, so the empty-log
/// 404 path is exercised via an unknown explicit tree_size.)
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn kt_proof_404_for_unknown_tree_size() {
    let pool = fresh_pool().await;
    let kt = kt_state();
    let app = server::router(AppState {
        pool: pool.clone(),
        kt,
    });
    let (status, body) = get(app, "/v1/kt/proof?leaf=0&tree_size=999999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, citadel_proto::error::ErrorCode::NotFound);
}
