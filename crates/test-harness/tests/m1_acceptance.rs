//! M1 exit acceptance test (PLAN.md §9 M1 AC): driven through the REAL
//! running compose stack in the CI `compose-smoke` job.
//!
//! Covers, end to end against live HTTP + PostgreSQL:
//! - registration of 3 accounts and enrollment of a second device per
//!   account (ADR-0004) — the AC's "3 accounts, 2 devices each";
//! - the F1 step-5 self-check (docs/protocol/auth.md §3 step B): rebuild
//!   the client's own `KtLeaf` from its registration fields +
//!   `kt_appended_at` (issue 008), fetch the atomic proof+head pair, and
//!   verify inclusion client-side under the pinned log anchor (INV-4);
//! - challenge-response → bearer token per device (ADR-0003 §1–§2);
//! - KeyPackage publish and consuming cross-account fetch, one package per
//!   active device, exhaustion → `key_package_unavailable` (ADR-0003 §4);
//! - KT consistency between an old client-pinned head and the latest head
//!   (ADR-0001 §5's client anti-rollback check, server side).
//!
//! Ignored by default so plain `cargo test --workspace` stays infra-free,
//! but NEVER silently green: compose-smoke provisions the stack and runs
//! exactly these tests with `--include-ignored` (PLAN.md §13). A missing
//! stack is a hard failure via `require_stack`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use citadel_proto::auth::{
    challenge_signing_input, ChallengeRequest, ChallengeResponse, EnrollDeviceRequest,
    EnrollDeviceResponse, FetchKeyPackagesResponse, PublishKeyPackagesRequest,
    PublishKeyPackagesResponse, RegisterAccountRequest, RegisterAccountResponse, VerifyRequest,
    VerifyResponse,
};
use citadel_proto::credential::{
    endorsement_signing_input, DeviceCredential, DeviceCredentialTbs, DeviceEndorsement,
    DevicePublicKey, IdentityPublicKey, Signature,
};
use citadel_proto::error::ErrorCode;
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_proto::kt::{ConsistencyProof, KtLeaf, KtProofResponse, SignedTreeHead};
use test_harness::client::TestClient;
use test_harness::stack::{probe_client, require_stack};
use test_harness::testkeys::TestSigner;

/// The compose stack's pinned dev-only log seed (deploy/docker-compose.yml).
/// The harness is the client: it holds the log public key as a pinned
/// anchor (ADR-0001 §5) and never accepts a key the server hands it.
const DEV_LOG_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn log_anchor() -> [u8; 32] {
    let b64 = std::env::var("CITADEL_KT_LOG_SEED").unwrap_or_else(|_| DEV_LOG_SEED_B64.into());
    let seed = B64
        .decode(b64.trim())
        .expect("log anchor seed must be base64");
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .expect("log anchor seed must decode to 32 bytes");
    // Only the verifying half leaves the signer type (ADR-0001 §3).
    kt_log::TreeHeadSigner::from_seed(&seed).public_key()
}

struct AcDevice {
    device_id: DeviceId,
    key: TestSigner,
    token: String,
}

struct AcAccount {
    account_id: AccountId,
    identity: TestSigner,
    kt_leaf_index: u64,
    registration_head: SignedTreeHead,
    devices: Vec<AcDevice>,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn register_account(
    client: &TestClient,
    anchor: &[u8; 32],
    handle: &str,
    identity: TestSigner,
    first_device_key: TestSigner,
) -> AcAccount {
    let tbs = DeviceCredentialTbs {
        account_id: AccountId::new(),
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(first_device_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    let req = RegisterAccountRequest {
        handle: handle.into(),
        identity_pubkey: tbs.identity_pubkey,
        first_device: DeviceCredential { tbs, signature },
    };
    let resp: RegisterAccountResponse = client
        .post_json("/v1/accounts", &req)
        .await
        .expect("registration must succeed on the live stack");

    // The head must verify under the PINNED anchor (never a served key),
    // and it must be the head that covers this leaf (ADR-0003 §5).
    let sth = resp.kt_tree_head;
    assert!(
        kt_log::verify_tree_head(&sth, anchor),
        "registration head must verify under the pinned anchor"
    );
    assert_eq!(sth.tbs.tree_size, resp.kt_leaf_index + 1);

    // F1 step 5 / auth.md §3 step B: rebuild the leaf from our own fields
    // + kt_appended_at (issue 008) and verify inclusion client-side.
    let leaf = KtLeaf {
        account_id: resp.account_id,
        handle: handle.into(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        appended_at: resp.kt_appended_at,
    };
    let pair: KtProofResponse = client
        .get_json(&format!(
            "/v1/kt/proof?leaf={}&tree_size={}",
            resp.kt_leaf_index, sth.tbs.tree_size
        ))
        .await
        .expect("proof endpoint must answer for a registered leaf");
    assert_eq!(
        pair.signed_tree_head, sth,
        "proof endpoint must pair the exact registration head"
    );
    assert!(
        kt_log::verify_inclusion(&leaf, &pair.proof, &pair.signed_tree_head),
        "own leaf must verify against the paired head"
    );

    AcAccount {
        account_id: resp.account_id,
        identity,
        kt_leaf_index: resp.kt_leaf_index,
        registration_head: sth,
        devices: vec![AcDevice {
            device_id: resp.device_id,
            key: first_device_key,
            token: String::new(),
        }],
    }
}

/// Enroll a second device (ADR-0004): identity-signed credential plus the
/// first device's endorsement over the exact credential bytes, authorized
/// by the first device's bearer token.
async fn enroll_device(client: &TestClient, account: &AcAccount, new_key: TestSigner) -> AcDevice {
    let first = &account.devices[0];
    let tbs = DeviceCredentialTbs {
        account_id: account.account_id,
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(account.identity.public_key()),
        device_pubkey: DevicePublicKey(new_key.public_key()),
        issued_at: now_epoch(),
    };
    let signature = Signature(account.identity.sign(&tbs.signing_input()));
    let credential = DeviceCredential { tbs, signature };
    let endorsement = DeviceEndorsement {
        endorsing_device_id: first.device_id,
        signature: Signature(first.key.sign(&endorsement_signing_input(&credential))),
    };
    let resp: EnrollDeviceResponse = client
        .post_json_bearer(
            "/v1/devices",
            &first.token,
            &EnrollDeviceRequest {
                credential,
                endorsement,
            },
        )
        .await
        .expect("second-device enrollment must succeed (ADR-0004)");
    AcDevice {
        device_id: resp.device_id,
        key: new_key,
        token: String::new(),
    }
}

/// Challenge-response → bearer token, over the live endpoints (ADR-0003 §1–§2).
async fn authenticate(client: &TestClient, device_id: DeviceId, key: &TestSigner) -> String {
    let challenge: ChallengeResponse = client
        .post_json("/v1/auth/challenge", &ChallengeRequest { device_id })
        .await
        .expect("challenge issuance must succeed");
    assert_eq!(challenge.challenge.len(), 32);
    let verify: VerifyResponse = client
        .post_json(
            "/v1/auth/verify",
            &VerifyRequest {
                device_id,
                challenge: challenge.challenge.clone(),
                signature: Signature(
                    key.sign(&challenge_signing_input(device_id, &challenge.challenge)),
                ),
            },
        )
        .await
        .expect("challenge verification must issue a token");
    verify.token
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn m1_ac_registers_accounts_and_verifies_kt() {
    let http = probe_client().expect("harness probe client must build");
    let endpoints = require_stack(&http)
        .await
        .expect("compose stack must be up; CI provisions it before this test runs");
    let client = TestClient::new(http, endpoints.auth.clone());
    let anchor = log_anchor();

    // ---- Register 3 accounts with the F1 self-check, then enroll the
    // second device per account (ADR-0004) — the AC's "3 accounts, 2
    // devices each".
    let mut accounts = Vec::new();
    for i in 0..3u8 {
        let identity = TestSigner::from_seed([0xA0 + i; 32]);
        let first_device_key = TestSigner::from_seed([0xB0 + i; 32]);
        let mut account = register_account(
            &client,
            &anchor,
            &format!("ac-user-{i}"),
            identity,
            first_device_key,
        )
        .await;

        // The first device authenticates first: enrollment requires its
        // bearer token (ADR-0004 §1).
        account.devices[0].token = authenticate(
            &client,
            account.devices[0].device_id,
            &account.devices[0].key,
        )
        .await;
        let second = enroll_device(&client, &account, TestSigner::from_seed([0xC0 + i; 32])).await;
        account.devices.push(second);
        assert_eq!(account.devices.len(), 2, "M1 AC: 2 devices per account");

        accounts.push(account);
    }

    // Leaf indexes are distinct and monotone in registration order.
    for w in accounts.windows(2) {
        assert!(w[0].kt_leaf_index < w[1].kt_leaf_index);
    }

    // ---- Every device authenticates (first devices already hold a token
    // from enrollment) and publishes to its pool. Package bytes are unique
    // per device so the fetch below can assert the exact drain set.
    for (ai, account) in accounts.iter_mut().enumerate() {
        for (di, device) in account.devices.iter_mut().enumerate() {
            if device.token.is_empty() {
                device.token = authenticate(&client, device.device_id, &device.key).await;
            }
            let packages = [
                format!("ac-pkg-a{ai}-d{di}-1").into_bytes(),
                format!("ac-pkg-a{ai}-d{di}-2").into_bytes(),
            ];
            let resp: PublishKeyPackagesResponse = client
                .post_json_bearer(
                    &format!("/v1/devices/{}/key-packages", device.device_id),
                    &device.token,
                    &PublishKeyPackagesRequest {
                        packages: packages
                            .iter()
                            .map(|p| citadel_proto::auth::KeyPackageBytes(p.clone()))
                            .collect(),
                    },
                )
                .await
                .expect("publish must succeed for the device's own token");
            assert_eq!(resp.pool_size, 2);
        }
    }

    // ---- Consuming cross-account fetch (F2 shape): account 1's device
    // fetches account 0's packages — one package per ACTIVE device per
    // call, all-or-nothing (ADR-0003 §4). Two devices × two packages means
    // exactly two rounds drain the account, then key_package_unavailable.
    let fetcher = &accounts[1].devices[0];
    let target = accounts[0].account_id;
    for round in 1..=2u8 {
        let fetched: FetchKeyPackagesResponse = client
            .get_json_bearer(
                &format!("/v1/accounts/{target}/key-packages"),
                &fetcher.token,
            )
            .await
            .expect("consuming fetch must succeed while the pool is stocked");
        assert_eq!(fetched.packages.len(), 2, "one package per active device");
        let got: std::collections::HashSet<(DeviceId, Vec<u8>)> = fetched
            .packages
            .iter()
            .map(|p| (p.device_id, p.package.0.clone()))
            .collect();
        let want: std::collections::HashSet<(DeviceId, Vec<u8>)> = accounts[0]
            .devices
            .iter()
            .enumerate()
            .map(|(di, d)| (d.device_id, format!("ac-pkg-a0-d{di}-{round}").into_bytes()))
            .collect();
        assert_eq!(got, want, "round {round} must drain exactly one per device");
    }
    let (status, err) = client
        .get_json_bearer_expect_error(
            &format!("/v1/accounts/{target}/key-packages"),
            &fetcher.token,
        )
        .await
        .expect("pool exhaustion must be a wire error");
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    assert_eq!(err.code, ErrorCode::KeyPackageUnavailable);

    // ---- KT consistency: the first account's pinned head provably extends
    // to the latest head (ADR-0001 §5 client anti-rollback, server side).
    let latest: SignedTreeHead = client
        .get_json("/v1/kt/tree-head")
        .await
        .expect("tree-head endpoint must answer");
    assert!(kt_log::verify_tree_head(&latest, &anchor));
    let oldest = accounts[0].registration_head;
    assert!(latest.tbs.tree_size >= oldest.tbs.tree_size);
    let proof: ConsistencyProof = client
        .get_json(&format!(
            "/v1/kt/consistency?first={}&second={}",
            oldest.tbs.tree_size, latest.tbs.tree_size
        ))
        .await
        .expect("consistency endpoint must answer between two persisted heads");
    assert!(
        kt_log::verify_consistency(&oldest, &latest, &proof),
        "latest head must provably extend the first pinned head"
    );
}
