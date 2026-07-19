//! ADR-0003 Evidence tests for registration and the KeyPackage pool
//! endpoints (§4 batch cap, §6 handle validation), plus the atomic
//! registration ↔ KT-append property (ADR-0001 §4(b)).
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.

use std::sync::Arc;

use auth_service::auth;
use auth_service::server::{self, AppState, KtState};
use auth_service::store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use citadel_proto::auth::{
    challenge_signing_input, FetchKeyPackagesResponse, PublishKeyPackagesResponse,
    RegisterAccountRequest, RegisterAccountResponse,
};
use citadel_proto::credential::{
    DeviceCredential, DeviceCredentialTbs, DevicePublicKey, IdentityPublicKey, Signature,
};
use citadel_proto::error::{ErrorCode, ErrorResponse};
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_proto::kt::{KtLeaf, KtProofResponse};
use kt_log::{KtLog, TreeHeadSigner};
use serde::de::DeserializeOwned;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use test_harness::testkeys::TestSigner;
use tower::ServiceExt;

const LOG_SEED: [u8; 32] = [0xA5; 32];

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the registration/pool tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate in a per-test schema. Registration appends to the
/// GLOBALLY sequenced kt_leaves (leaf index = seq - 1, ADR-0001 §4), so a
/// test must own its sequence — see kt_persistence.rs for the failure this
/// prevents. Isolation is a fresh schema per case, never TRUNCATE.
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

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn app(pool: &PgPool) -> (axum::Router, Arc<KtState>) {
    let kt = Arc::new(KtState {
        log: tokio::sync::Mutex::new(KtLog::new()),
        signer: TreeHeadSigner::from_seed(&LOG_SEED),
    });
    (
        server::router(AppState {
            pool: pool.clone(),
            kt: kt.clone(),
        }),
        kt,
    )
}

fn post(uri: &str, body: Vec<u8>, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body)).unwrap()
}

async fn call<T: DeserializeOwned>(app: axum::Router, req: Request<Body>) -> (StatusCode, T) {
    let target = format!("{} {}", req.method(), req.uri());
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{target} returned {status} with an unparseable body ({e}): {:?}",
                String::from_utf8_lossy(&bytes)
            )
        }),
    )
}

fn registration_request(
    identity: &TestSigner,
    device_key: &TestSigner,
    handle: &str,
) -> RegisterAccountRequest {
    let tbs = DeviceCredentialTbs {
        account_id: AccountId::new(),
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(device_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    RegisterAccountRequest {
        handle: handle.into(),
        identity_pubkey: tbs.identity_pubkey,
        first_device: DeviceCredential { tbs, signature },
    }
}

struct Registered {
    account: AccountId,
    device: DeviceId,
    device_key: TestSigner,
    response: RegisterAccountResponse,
}

async fn register_ok(router: axum::Router, seed: u8, handle: &str) -> Registered {
    let identity = TestSigner::from_seed([seed; 32]);
    let device_key = TestSigner::from_seed([seed.wrapping_add(1); 32]);
    let req = registration_request(&identity, &device_key, handle);
    let (status, resp): (StatusCode, RegisterAccountResponse) = call(
        router,
        post("/v1/accounts", serde_json::to_vec(&req).unwrap(), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    Registered {
        account: resp.account_id,
        device: resp.device_id,
        device_key,
        response: resp,
    }
}

async fn issue_token(pool: &PgPool, device: DeviceId, device_key: &TestSigner) -> String {
    let c = auth::issue_challenge(pool, device).await.unwrap();
    let sig = device_key.sign(&challenge_signing_input(device, &c.challenge));
    auth::verify_challenge_and_issue_token(pool, device, &c.challenge, &sig)
        .await
        .unwrap()
        .token
}

/// ADR-0003 Evidence: 65-byte handle → `invalid_request` (and the empty
/// handle likewise); a 64-byte handle is accepted.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn registration_rejects_long_handles() {
    let pool = fresh_pool().await;
    let (router, _kt) = app(&pool);

    for bad in ["h".repeat(65), String::new()] {
        let identity = TestSigner::from_seed([0x10; 32]);
        let device_key = TestSigner::from_seed([0x11; 32]);
        let req = registration_request(&identity, &device_key, &bad);
        let (status, err): (StatusCode, ErrorResponse) = call(
            router.clone(),
            post("/v1/accounts", serde_json::to_vec(&req).unwrap(), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "handle {bad:?}");
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    // Boundary: exactly 64 bytes passes handle validation end to end.
    let reg = register_ok(router, 0x12, &"h".repeat(64)).await;
    assert_eq!(
        reg.response.kt_tree_head.tbs.tree_size,
        reg.response.kt_leaf_index + 1
    );
}

/// Registration is atomic with the KT append (ADR-0001 §4(b)): the
/// response's head covers the leaf, the leaf persists, and the proof
/// endpoint serves a pair the client verifies end to end.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn registration_appends_kt_leaf_atomically() {
    let pool = fresh_pool().await;
    let (router, _kt) = app(&pool);
    let handle = "atomic-alice";
    let identity = TestSigner::from_seed([0x20; 32]);
    let reg = register_ok(router.clone(), 0x20, handle).await;

    let index = reg.response.kt_leaf_index;
    let sth = reg.response.kt_tree_head;
    assert_eq!(sth.tbs.tree_size, index + 1);
    assert!(kt_log::verify_tree_head(
        &sth,
        &TreeHeadSigner::from_seed(&LOG_SEED).public_key()
    ));

    // The persisted leaf bytes are exactly KtLeaf::leaf_bytes() for the
    // registered fields (appended_at recovered from the tail of the bytes).
    let leaf_bytes: Vec<u8> = sqlx::query("SELECT leaf_bytes FROM kt_leaves WHERE seq = $1")
        .bind(index as i64 + 1)
        .fetch_one(&pool)
        .await
        .map(|r| sqlx::Row::get(&r, "leaf_bytes"))
        .expect("leaf row exists at seq = index + 1");
    let appended_at = i64::from_be_bytes(leaf_bytes[leaf_bytes.len() - 8..].try_into().unwrap());
    let leaf = KtLeaf {
        account_id: reg.account,
        handle: handle.into(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        appended_at,
    };
    assert_eq!(leaf.leaf_bytes(), leaf_bytes);

    // The proof endpoint serves the verifiable pair for this leaf/head.
    let (status, pair): (StatusCode, KtProofResponse) = call(
        router.clone(),
        Request::builder()
            .uri(format!(
                "/v1/kt/proof?leaf={index}&tree_size={}",
                sth.tbs.tree_size
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(kt_log::verify_inclusion(
        &leaf,
        &pair.proof,
        &pair.signed_tree_head
    ));

    // Account and device rows landed with the leaf.
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = $1")
        .bind(reg.account.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE id = $1")
        .bind(reg.device.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((accounts, devices), (1, 1));

    // Re-registering the same account/device ids is a conflict, not a
    // duplicate leaf.
    let tbs = DeviceCredentialTbs {
        account_id: reg.account,
        device_id: reg.device,
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(reg.device_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    let dup = RegisterAccountRequest {
        handle: handle.into(),
        identity_pubkey: tbs.identity_pubkey,
        first_device: DeviceCredential { tbs, signature },
    };
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post("/v1/accounts", serde_json::to_vec(&dup).unwrap(), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(err.code, ErrorCode::Conflict);
}

/// ADR-0003 Evidence: a 101-package publish is `invalid_request`.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn publish_rejects_oversized_batch() {
    let pool = fresh_pool().await;
    let (router, _kt) = app(&pool);
    let packages: Vec<String> = (0..101)
        .map(|i| base64::engine::general_purpose::STANDARD.encode(format!("pkg-{i}")))
        .collect();
    let body = serde_json::json!({ "packages": packages });
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices/00000000-0000-0000-0000-000000000000/key-packages",
            serde_json::to_vec(&body).unwrap(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, ErrorCode::InvalidRequest);
}

/// Pool endpoints end to end: publish (self only, bearer auth), consuming
/// fetch one-per-device, and all-or-nothing exhaustion → 409.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn publish_fetch_roundtrip_and_all_or_nothing() {
    let pool = fresh_pool().await;
    let (router, _kt) = app(&pool);
    let reg = register_ok(router.clone(), 0x30, "pool-owner").await;
    let token = issue_token(&pool, reg.device, &reg.device_key).await;
    let publish_uri = format!("/v1/devices/{}/key-packages", reg.device);

    // Publish requires a bearer token.
    let body = serde_json::json!({ "packages": ["cGtn"] });
    let (status, _): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post(&publish_uri, serde_json::to_vec(&body).unwrap(), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A device publishes only for itself.
    let other = register_ok(router.clone(), 0x40, "pool-other").await;
    let other_token = issue_token(&pool, other.device, &other.device_key).await;
    let (status, err): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post(
            &publish_uri,
            serde_json::to_vec(&body).unwrap(),
            Some(&other_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, ErrorCode::Forbidden);

    // Publish two, pool size reported in the response (ADR-0003 §4).
    // (proto's b64 helpers are standard-WITH-padding; encode, don't
    // hand-write — the first CI run failed here on "cGtnLTE" missing '='.)
    let published: Vec<Vec<u8>> = vec![b"pkg-1".to_vec(), b"pkg-2".to_vec()];
    let body = serde_json::json!({
        "packages": published
            .iter()
            .map(|p| base64::engine::general_purpose::STANDARD.encode(p))
            .collect::<Vec<_>>()
    });
    let (status, resp): (StatusCode, PublishKeyPackagesResponse) = call(
        router.clone(),
        post(
            &publish_uri,
            serde_json::to_vec(&body).unwrap(),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp.pool_size, 2);

    // Consuming fetch: one package per active device per call.
    let fetch_uri = format!("/v1/accounts/{}/key-packages", reg.account);
    for want_remaining in [1usize, 0] {
        let (status, fetched): (StatusCode, FetchKeyPackagesResponse) = call(
            router.clone(),
            Request::builder()
                .uri(&fetch_uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched.packages.len(), 1);
        assert_eq!(fetched.packages[0].device_id, reg.device);
        // Oldest-first: fetches drain the published packages in order.
        assert_eq!(fetched.packages[0].package.0, published[1 - want_remaining]);
        let remaining = auth_service::store::unconsumed_count(&pool, reg.device)
            .await
            .unwrap();
        assert_eq!(remaining, want_remaining as u32);
    }

    // Empty pool for the account's only device → 409, nothing burned.
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        Request::builder()
            .uri(&fetch_uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(err.code, ErrorCode::KeyPackageUnavailable);
}
