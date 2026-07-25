//! ADR-0003 Evidence tests for the challenge-response / token flow.
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.
//!
//! Client signatures come from test-harness's TestSigner: services are
//! crypto-confined (ADR-0002 §4, dev-deps included), so no signing crate
//! may appear here even for tests.

use auth_service::auth::{self, AuthError, CHALLENGE_TTL_SECS, TOKEN_TTL_SECS};
use auth_service::server::{self, AppState, KtState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use citadel_proto::auth::{
    challenge_signing_input, ChallengeRequest, ChallengeResponse, VerifyRequest, VerifyResponse,
};
use citadel_proto::credential::Signature;
use citadel_proto::error::ErrorCode;
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_service_crypto as crypto;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use test_harness::testkeys::TestSigner;
use tower::ServiceExt;

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the auth flow tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate. Parallel tests share ONE database; isolation comes
/// from fresh random account/device UUIDs per case — never TRUNCATE (see
/// key_package_pool.rs for the race that taught this).
async fn fresh_pool() -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(16)
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

async fn make_device(pool: &PgPool, account: AccountId, device_pubkey: &[u8; 32]) -> DeviceId {
    let id = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices (id, account_id, device_pubkey, credential) VALUES ($1, $2, $3, $4)",
    )
    .bind(id.as_uuid())
    .bind(account.as_uuid())
    .bind(&device_pubkey[..])
    .bind(vec![0xCCu8; 16])
    .execute(pool)
    .await
    .expect("insert device");
    id
}

/// Full store-level flow: challenge, sign, verify, token.
async fn issue_token(pool: &PgPool, device: DeviceId, key: &TestSigner) -> auth::IssuedToken {
    let challenge = auth::issue_challenge(pool, device)
        .await
        .expect("issue challenge");
    let signature = key.sign(&challenge_signing_input(device, &challenge.challenge));
    auth::verify_challenge_and_issue_token(pool, device, &challenge.challenge, &signature)
        .await
        .expect("verify challenge and issue token")
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// ADR-0003 Evidence: replay of a consumed/expired challenge is rejected;
/// a new challenge replaces the outstanding one.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn auth_challenge_single_use_and_expiry() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let key = TestSigner::from_seed([0x11; 32]);
    let device = make_device(&pool, account, &key.public_key()).await;

    // A new challenge replaces the outstanding one: only the latest answers.
    let c1 = auth::issue_challenge(&pool, device).await.unwrap();
    let c2 = auth::issue_challenge(&pool, device).await.unwrap();
    assert_ne!(c1.challenge, c2.challenge);
    let sig_c2 = key.sign(&challenge_signing_input(device, &c2.challenge));
    auth::verify_challenge_and_issue_token(&pool, device, &c2.challenge, &sig_c2)
        .await
        .expect("latest challenge verifies");
    assert!(matches!(
        auth::verify_challenge_and_issue_token(
            &pool,
            device,
            &c1.challenge,
            &key.sign(&challenge_signing_input(device, &c1.challenge)),
        )
        .await,
        Err(AuthError::Unauthorized)
    ));

    // Replay of the consumed challenge is rejected.
    assert!(matches!(
        auth::verify_challenge_and_issue_token(&pool, device, &c2.challenge, &sig_c2).await,
        Err(AuthError::Unauthorized)
    ));

    // A failed attempt consumes the challenge too (anti-replay).
    let c3 = auth::issue_challenge(&pool, device).await.unwrap();
    let wrong_key = TestSigner::from_seed([0x22; 32]);
    let bad_sig = wrong_key.sign(&challenge_signing_input(device, &c3.challenge));
    assert!(matches!(
        auth::verify_challenge_and_issue_token(&pool, device, &c3.challenge, &bad_sig).await,
        Err(AuthError::Unauthorized)
    ));
    let good_sig = key.sign(&challenge_signing_input(device, &c3.challenge));
    assert!(matches!(
        auth::verify_challenge_and_issue_token(&pool, device, &c3.challenge, &good_sig).await,
        Err(AuthError::Unauthorized)
    ));

    // An expired challenge is rejected (and consumed).
    let c4 = auth::issue_challenge(&pool, device).await.unwrap();
    sqlx::query(
        "UPDATE auth_challenges SET expires_at = now() - interval '1 second' WHERE device_id = $1",
    )
    .bind(device.as_uuid())
    .execute(&pool)
    .await
    .expect("backdate challenge");
    let sig_c4 = key.sign(&challenge_signing_input(device, &c4.challenge));
    assert!(matches!(
        auth::verify_challenge_and_issue_token(&pool, device, &c4.challenge, &sig_c4).await,
        Err(AuthError::Unauthorized)
    ));
}

/// ADR-0003 Evidence: the token column contains no token bytes
/// (scan-style assertion over `auth_tokens`).
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn auth_token_hashed_at_rest() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let key = TestSigner::from_seed([0x33; 32]);
    let device = make_device(&pool, account, &key.public_key()).await;

    let issued = issue_token(&pool, device, &key).await;
    let raw = URL_SAFE_NO_PAD
        .decode(&issued.token)
        .expect("token is base64url");
    assert_eq!(raw.len(), 32, "token is 32 raw bytes (ADR-0003 §2)");

    // TTL is the ADR's 24 h, within clock slack.
    let ttl = issued.expires_at - now_epoch();
    assert!((TOKEN_TTL_SECS - 60..=TOKEN_TTL_SECS).contains(&ttl));

    // Scan every column of every auth_tokens row as text: neither the wire
    // form nor the raw bytes (hex) nor their base64 may appear anywhere.
    let rows = sqlx::query(
        "SELECT encode(token_hash, 'hex') AS th, device_id::text AS d, \
         issued_at::text AS i, expires_at::text AS e, \
         coalesce(revoked_at::text, '') AS r FROM auth_tokens",
    )
    .fetch_all(&pool)
    .await
    .expect("scan auth_tokens");
    assert!(!rows.is_empty());
    let raw_hex = hex_lower(&raw);
    let raw_b64 = URL_SAFE_NO_PAD.encode(&raw);
    for row in &rows {
        let dump: String = ["th", "d", "i", "e", "r"]
            .iter()
            .map(|c| row.get::<String, _>(*c))
            .collect();
        assert!(!dump.contains(&issued.token), "wire token leaked at rest");
        assert!(!dump.contains(&raw_hex), "raw token bytes leaked at rest");
        assert!(!dump.contains(&raw_b64), "raw token base64 leaked at rest");
    }

    // What IS stored is exactly SHA-256(raw token) — and nothing reversible.
    let stored: Vec<u8> = sqlx::query("SELECT token_hash FROM auth_tokens WHERE device_id = $1")
        .bind(device.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("fetch token row")
        .get("token_hash");
    assert_eq!(stored, crypto::sha256(&raw));
}

/// ADR-0003 Evidence: revoking a device kills its tokens immediately.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn device_revocation_invalidates_tokens_immediately() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let key = TestSigner::from_seed([0x44; 32]);
    let device = make_device(&pool, account, &key.public_key()).await;

    let issued = issue_token(&pool, device, &key).await;
    assert_eq!(
        auth::validate_token(&pool, &issued.token)
            .await
            .expect("token valid"),
        device
    );

    auth::revoke_device(&pool, device)
        .await
        .expect("revoke device");
    assert!(matches!(
        auth::validate_token(&pool, &issued.token).await,
        Err(AuthError::Unauthorized)
    ));
}

/// ADR-0003 Evidence: suspension cascades to `devices.revoked_at` for
/// every device of the account; its tokens are rejected immediately after.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn account_suspension_revokes_all_device_tokens() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let key_a = TestSigner::from_seed([0x55; 32]);
    let key_b = TestSigner::from_seed([0x66; 32]);
    let device_a = make_device(&pool, account, &key_a.public_key()).await;
    let device_b = make_device(&pool, account, &key_b.public_key()).await;

    let token_a = issue_token(&pool, device_a, &key_a).await;
    let token_b = issue_token(&pool, device_b, &key_b).await;
    assert!(auth::validate_token(&pool, &token_a.token).await.is_ok());
    assert!(auth::validate_token(&pool, &token_b.token).await.is_ok());

    let revoked = auth::suspend_account(&pool, account)
        .await
        .expect("suspend account");
    assert_eq!(revoked, 2, "one write revoked both devices");

    assert!(matches!(
        auth::validate_token(&pool, &token_a.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        auth::validate_token(&pool, &token_b.token).await,
        Err(AuthError::Unauthorized)
    ));

    // A suspended account's devices can no longer even start the flow.
    assert!(matches!(
        auth::issue_challenge(&pool, device_a).await,
        Err(AuthError::Unauthorized)
    ));
}

/// Endpoint-level roundtrip over the real router: the HTTP edge speaks the
/// proto shapes and maps auth failure to `unauthorized`.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn challenge_verify_endpoints_roundtrip() {
    let pool = fresh_pool().await;
    let account = make_account(&pool).await;
    let key = TestSigner::from_seed([0x77; 32]);
    let device = make_device(&pool, account, &key.public_key()).await;
    let app = server::router(AppState {
        pool: pool.clone(),
        kt: std::sync::Arc::new(KtState {
            log: tokio::sync::Mutex::new(kt_log::KtLog::new()),
            signer: kt_log::TreeHeadSigner::from_seed(&[0xA5; 32]),
        }),
    });

    let post = |path: &str, body: Vec<u8>| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };

    // Challenge issuance.
    let resp = app
        .clone()
        .oneshot(post(
            "/v1/auth/challenge",
            serde_json::to_vec(&ChallengeRequest { device_id: device }).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let challenge: ChallengeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(challenge.challenge.len(), 32);
    let ttl = challenge.expires_at - now_epoch();
    assert!((CHALLENGE_TTL_SECS - 60..=CHALLENGE_TTL_SECS).contains(&ttl));

    // A bad signature is unauthorized, never a 500.
    let bad = VerifyRequest {
        device_id: device,
        challenge: challenge.challenge.clone(),
        signature: Signature([0xEE; 64]),
    };
    let resp = app
        .clone()
        .oneshot(post("/v1/auth/verify", serde_json::to_vec(&bad).unwrap()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let err: citadel_proto::error::ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::Unauthorized);

    // Full roundtrip on a fresh challenge yields a bearer token.
    let resp = app
        .clone()
        .oneshot(post(
            "/v1/auth/challenge",
            serde_json::to_vec(&ChallengeRequest { device_id: device }).unwrap(),
        ))
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let challenge: ChallengeResponse = serde_json::from_slice(&body).unwrap();
    let good = VerifyRequest {
        device_id: device,
        challenge: challenge.challenge.clone(),
        signature: Signature(key.sign(&challenge_signing_input(device, &challenge.challenge))),
    };
    let resp = app
        .oneshot(post("/v1/auth/verify", serde_json::to_vec(&good).unwrap()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let token: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        auth::validate_token(&pool, &token.token)
            .await
            .expect("token valid"),
        device
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
