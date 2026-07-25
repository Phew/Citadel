//! ADR-0004 Evidence tests for device enrollment (`POST /v1/devices`).
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.

use std::sync::Arc;

use auth_service::auth;
use auth_service::server::{self, AppState, KtState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citadel_proto::auth::{
    challenge_signing_input, EnrollDeviceRequest, EnrollDeviceResponse, RegisterAccountRequest,
    RegisterAccountResponse,
};
use citadel_proto::credential::{
    endorsement_signing_input, DeviceCredential, DeviceCredentialTbs, DeviceEndorsement,
    DevicePublicKey, IdentityPublicKey, Signature,
};
use citadel_proto::error::{ErrorCode, ErrorResponse};
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_proto::kt::SignedTreeHead;
use kt_log::{KtLog, TreeHeadSigner};
use serde::de::DeserializeOwned;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use test_harness::testkeys::TestSigner;
use tower::ServiceExt;

const LOG_SEED: [u8; 32] = [0xA5; 32];

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the enrollment tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate in a THROWAWAY per-test database. Registration
/// appends to the GLOBALLY sequenced kt_leaves (leaf index = seq - 1,
/// ADR-0001 §4), so a test must own its sequence — see kt_persistence.rs
/// for the failure this prevents. The canonical runner pins search_path to
/// public (ADR-0006 §1), so the pre-ADR-0006 per-test SCHEMA isolation no
/// longer applies; a fresh DATABASE per case is the same philosophy (never
/// TRUNCATE) through the one canonical entry point.
struct TestDb {
    name: String,
    admin: PgPool,
}

impl TestDb {
    async fn teardown(self) {
        // WITH (FORCE) disconnects stragglers (PG13+). A panicked test leaks
        // its database — acceptable: CI's postgres is ephemeral per job and
        // names are unique per case.
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            self.name
        ))
        .execute(&self.admin)
        .await
        .expect("drop test database");
    }
}

async fn fresh_pool() -> (TestDb, PgPool) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url())
        .await
        .expect("connect to real PostgreSQL (CI provisions it)");
    let name = format!("citadel_t_{}", AccountId::new().as_uuid().simple());
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await
        .expect("create per-test database");

    let base = db_url()
        .rsplit_once('/')
        .map(|(b, _)| b.to_string())
        .expect("DATABASE_URL must end in a database name");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&format!("{base}/{name}"))
        .await
        .expect("connect to per-test database");
    citadel_migrations::migrate(&pool)
        .await
        .expect("apply canonical migrations (ADR-0006)");
    (TestDb { name, admin }, pool)
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn app(pool: &PgPool) -> axum::Router {
    server::router(AppState {
        pool: pool.clone(),
        kt: Arc::new(KtState {
            log: tokio::sync::Mutex::new(KtLog::new()),
            signer: TreeHeadSigner::from_seed(&LOG_SEED),
        }),
    })
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

struct Fixture {
    account: AccountId,
    device_a: DeviceId,
    identity: TestSigner,
    device_a_key: TestSigner,
    token_a: String,
}

/// Register an account through the endpoint and authenticate device A.
async fn setup_account(router: axum::Router, pool: &PgPool, seed: u8) -> Fixture {
    let identity = TestSigner::from_seed([seed; 32]);
    let device_a_key = TestSigner::from_seed([seed.wrapping_add(1); 32]);
    let tbs = DeviceCredentialTbs {
        account_id: AccountId::new(),
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(device_a_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    let req = RegisterAccountRequest {
        handle: format!("enroll-user-{seed:02x}"),
        identity_pubkey: tbs.identity_pubkey,
        first_device: DeviceCredential { tbs, signature },
    };
    let (status, resp): (StatusCode, RegisterAccountResponse) = call(
        router,
        post("/v1/accounts", serde_json::to_vec(&req).unwrap(), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let challenge = auth::issue_challenge(pool, resp.device_id).await.unwrap();
    let sig = device_a_key.sign(&challenge_signing_input(
        resp.device_id,
        &challenge.challenge,
    ));
    let token_a =
        auth::verify_challenge_and_issue_token(pool, resp.device_id, &challenge.challenge, &sig)
            .await
            .unwrap()
            .token;

    Fixture {
        account: resp.account_id,
        device_a: resp.device_id,
        identity,
        device_a_key,
        token_a,
    }
}

/// A fully valid enrollment request for a new device (identity-signed
/// credential + device A's endorsement over the exact credential bytes).
fn enroll_request(fx: &Fixture, new_device: DeviceId, new_key: &TestSigner) -> EnrollDeviceRequest {
    let tbs = DeviceCredentialTbs {
        account_id: fx.account,
        device_id: new_device,
        identity_pubkey: IdentityPublicKey(fx.identity.public_key()),
        device_pubkey: DevicePublicKey(new_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(fx.identity.sign(&tbs.signing_input()));
    let credential = DeviceCredential { tbs, signature };
    let endorsement = DeviceEndorsement {
        endorsing_device_id: fx.device_a,
        signature: Signature(
            fx.device_a_key
                .sign(&endorsement_signing_input(&credential)),
        ),
    };
    EnrollDeviceRequest {
        credential,
        endorsement,
    }
}

async fn device_row_count(pool: &PgPool, device: DeviceId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM devices WHERE id = $1")
        .bind(device.as_uuid())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// ADR-0004 Evidence: enroll device B (identity-signed credential + A's
/// endorsement + A's bearer token); B then completes ADR-0003 §1
/// challenge-response and obtains its own token; both devices active.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_second_device_succeeds_then_authenticates() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x10).await;

    let device_b = DeviceId::new();
    let key_b = TestSigner::from_seed([0x12; 32]);
    let req = enroll_request(&fx, device_b, &key_b);
    let (status, resp): (StatusCode, EnrollDeviceResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp.device_id, device_b);

    // B proves possession at its first challenge-response (ADR-0004 §4).
    let challenge = auth::issue_challenge(&pool, device_b).await.unwrap();
    let sig = key_b.sign(&challenge_signing_input(device_b, &challenge.challenge));
    let token_b =
        auth::verify_challenge_and_issue_token(&pool, device_b, &challenge.challenge, &sig)
            .await
            .unwrap()
            .token;
    assert_eq!(
        auth::validate_token(&pool, &token_b).await.unwrap(),
        device_b
    );

    // Both devices are active for the account.
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE account_id = $1 AND revoked_at IS NULL",
    )
    .bind(fx.account.as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 2);
    db.teardown().await;
}

/// ADR-0004 Evidence: absent / expired / revoked token → `unauthorized`;
/// no `devices` row is created.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_requires_valid_bearer_token() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x20).await;

    // Absent token.
    let device_b = DeviceId::new();
    let req = enroll_request(&fx, device_b, &TestSigner::from_seed([0x22; 32]));
    let (status, err): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post("/v1/devices", serde_json::to_vec(&req).unwrap(), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // Expired token.
    sqlx::query(
        "UPDATE auth_tokens SET expires_at = now() - interval '1 second' WHERE device_id = $1",
    )
    .bind(fx.device_a.as_uuid())
    .execute(&pool)
    .await
    .unwrap();
    let (status, _): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revoked token's device (fresh token first, then revoke the device).
    let challenge = auth::issue_challenge(&pool, fx.device_a).await.unwrap();
    let sig = fx
        .device_a_key
        .sign(&challenge_signing_input(fx.device_a, &challenge.challenge));
    let token =
        auth::verify_challenge_and_issue_token(&pool, fx.device_a, &challenge.challenge, &sig)
            .await
            .unwrap()
            .token;
    auth::revoke_device(&pool, fx.device_a).await.unwrap();
    let (status, _): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    assert_eq!(device_row_count(&pool, device_b).await, 0);
    db.teardown().await;
}

/// ADR-0004 Evidence: a credential not signed by the account identity key
/// → `unauthorized`; no row created.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_rejects_bad_identity_signature() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x30).await;

    let device_b = DeviceId::new();
    let wrong_identity = TestSigner::from_seed([0x3E; 32]);
    let tbs = DeviceCredentialTbs {
        account_id: fx.account,
        device_id: device_b,
        identity_pubkey: IdentityPublicKey(fx.identity.public_key()), // claims the real identity
        device_pubkey: DevicePublicKey(TestSigner::from_seed([0x32; 32]).public_key()),
        issued_at: now_epoch(),
    };
    // ...but signed by a DIFFERENT key.
    let signature = Signature(wrong_identity.sign(&tbs.signing_input()));
    let credential = DeviceCredential { tbs, signature };
    let req = EnrollDeviceRequest {
        credential: credential.clone(),
        endorsement: DeviceEndorsement {
            endorsing_device_id: fx.device_a,
            signature: Signature(
                fx.device_a_key
                    .sign(&endorsement_signing_input(&credential)),
            ),
        },
    };
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.code, ErrorCode::Unauthorized);
    assert_eq!(device_row_count(&pool, device_b).await, 0);
    db.teardown().await;
}

/// ADR-0004 Evidence: `credential.tbs.identity_pubkey` ≠ the account's
/// stored identity → `unauthorized`.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_rejects_identity_pubkey_mismatch() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x40).await;

    let device_b = DeviceId::new();
    let other_identity = TestSigner::from_seed([0x4E; 32]);
    let tbs = DeviceCredentialTbs {
        account_id: fx.account,
        device_id: device_b,
        identity_pubkey: IdentityPublicKey(other_identity.public_key()), // not the account's identity
        device_pubkey: DevicePublicKey(TestSigner::from_seed([0x42; 32]).public_key()),
        issued_at: now_epoch(),
    };
    // Signature is valid under the OTHER identity — the binding is the lie.
    let signature = Signature(other_identity.sign(&tbs.signing_input()));
    let credential = DeviceCredential { tbs, signature };
    let req = EnrollDeviceRequest {
        credential: credential.clone(),
        endorsement: DeviceEndorsement {
            endorsing_device_id: fx.device_a,
            signature: Signature(
                fx.device_a_key
                    .sign(&endorsement_signing_input(&credential)),
            ),
        },
    };
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.code, ErrorCode::Unauthorized);
    assert_eq!(device_row_count(&pool, device_b).await, 0);
    db.teardown().await;
}

/// ADR-0004 Evidence: endorsement by a device of another account, or
/// `endorsing_device_id != token.device_id`, or an invalid endorsement
/// signature → `forbidden`/`unauthorized`; no row created.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_rejects_foreign_or_mismatched_endorsement() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x50).await;
    let foreign = setup_account(router.clone(), &pool, 0x58).await;

    // (a) endorsing_device_id is not the calling device → forbidden.
    let device_b = DeviceId::new();
    let mut req = enroll_request(&fx, device_b, &TestSigner::from_seed([0x52; 32]));
    req.endorsement.endorsing_device_id = DeviceId::new();
    let (status, err): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, ErrorCode::Forbidden);

    // (b) endorsement signed by a key that is not device A's → unauthorized.
    let mut req = enroll_request(&fx, device_b, &TestSigner::from_seed([0x52; 32]));
    req.endorsement.signature = Signature(
        TestSigner::from_seed([0x5E; 32]).sign(&endorsement_signing_input(&req.credential)),
    );
    let (status, err): (StatusCode, ErrorResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // (c) endorsement by a device of ANOTHER account (its id is not the
    // calling device) → forbidden.
    let mut req = enroll_request(&fx, device_b, &TestSigner::from_seed([0x52; 32]));
    req.endorsement.endorsing_device_id = foreign.device_a;
    req.endorsement.signature = Signature(
        foreign
            .device_a_key
            .sign(&endorsement_signing_input(&req.credential)),
    );
    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, ErrorCode::Forbidden);

    assert_eq!(device_row_count(&pool, device_b).await, 0);
    db.teardown().await;
}

/// ADR-0004 Evidence: replay of a completed enrollment → `conflict` (409);
/// exactly one `devices` row exists for that id.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_rejects_duplicate_device_id() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x60).await;

    let device_b = DeviceId::new();
    let req = enroll_request(&fx, device_b, &TestSigner::from_seed([0x62; 32]));
    let (status, _): (StatusCode, EnrollDeviceResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, err): (StatusCode, ErrorResponse) = call(
        router,
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(err.code, ErrorCode::Conflict);
    assert_eq!(device_row_count(&pool, device_b).await, 1);
    db.teardown().await;
}

/// ADR-0004 Evidence: enrollment does not grow the KT log (§"KT log") —
/// `GET /v1/kt/tree-head` reports the same tree_size before and after.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn enroll_does_not_grow_kt_log() {
    let (db, pool) = fresh_pool().await;
    let router = app(&pool);
    let fx = setup_account(router.clone(), &pool, 0x70).await;

    let get_tree_size = |router: axum::Router| async move {
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/v1/kt/tree-head")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice::<SignedTreeHead>(&bytes)
            .unwrap()
            .tbs
            .tree_size
    };
    let before = get_tree_size(router.clone()).await;

    let req = enroll_request(&fx, DeviceId::new(), &TestSigner::from_seed([0x72; 32]));
    let (status, _): (StatusCode, EnrollDeviceResponse) = call(
        router.clone(),
        post(
            "/v1/devices",
            serde_json::to_vec(&req).unwrap(),
            Some(&fx.token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let after = get_tree_size(router).await;
    assert_eq!(before, after, "enrollment must not append to the KT log");
    db.teardown().await;
}
