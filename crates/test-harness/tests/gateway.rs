//! M2 gateway stack tests (ADR-0005 §1 Evidence): driven through the REAL
//! running compose stack in the CI `compose-smoke` job
//! (`cargo test -p test-harness -- --include-ignored`), same pattern as the
//! M1 acceptance test.
//!
//! - `f2_gateway_welcome_delivery` — the transport half of F2: founding
//!   Welcome → on-connect push to the addressee → subscribe → live fanout →
//!   `?after=` sync. Payloads are opaque stand-ins for serialized OpenMLS
//!   `MlsMessageOut` bytes: the MLS-backed F2/F4 (group create/join,
//!   credential verification against the KT log, padding, decrypt) land with
//!   citadel-core; this test pins the delivery transport they will ride.
//! - `subscribe_rejects_non_addressee` — a device with no delivery metadata
//!   in G gets an `Error` frame and no fanout for G (decision #5:
//!   spam-hygiene authorization), and its REST submit gets 403
//!   (Amendment 1 §B).
//!
//! Ignored by default so plain `cargo test --workspace` stays infra-free,
//! but NEVER silently green: a missing stack is a hard failure via
//! `require_stack` (PLAN.md §13).

use std::time::Duration;

use citadel_proto::auth::{
    challenge_signing_input, ChallengeRequest, ChallengeResponse, RegisterAccountRequest,
    RegisterAccountResponse, VerifyRequest, VerifyResponse,
};
use citadel_proto::credential::{
    DeviceCredential, DeviceCredentialTbs, DevicePublicKey, IdentityPublicKey, Signature,
};
use citadel_proto::delivery::{
    GatewayClientFrame, GatewayServerFrame, MessagesPage, SubmitMessageRequest,
    SubmitMessageResponse,
};
use citadel_proto::envelope::{Envelope, EnvelopeKind};
use citadel_proto::error::ErrorCode;
use citadel_proto::ids::{AccountId, DeviceId, GroupId};
use futures_util::{SinkExt, StreamExt};
use test_harness::client::TestClient;
use test_harness::stack::{probe_client, require_stack};
use test_harness::testkeys::TestSigner;
use tokio_tungstenite::tungstenite;

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// A registered account's first device with a live bearer token.
struct TestDevice {
    device_id: DeviceId,
    token: String,
}

/// Minimal register + challenge/verify (ADR-0003 §1–§2, §6) against the
/// auth-service. The M1 acceptance test owns the KT-verification variant;
/// the gateway tests only need an authenticated device.
async fn register_and_authenticate(client: &TestClient, seed: u8) -> TestDevice {
    let identity = TestSigner::from_seed([seed; 32]);
    let device_key = TestSigner::from_seed([seed.wrapping_add(1); 32]);
    let tbs = DeviceCredentialTbs {
        account_id: AccountId::new(),
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(device_key.public_key()),
        issued_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64,
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    // Unique handle per run: the compose DB persists across tests in a run.
    let handle = format!("gw-{seed:02x}-{}", uuid::Uuid::new_v4().simple());
    let resp: RegisterAccountResponse = client
        .post_json(
            "/v1/accounts",
            &RegisterAccountRequest {
                handle,
                identity_pubkey: tbs.identity_pubkey,
                first_device: DeviceCredential { tbs, signature },
            },
        )
        .await
        .expect("gateway-test registration must succeed");
    let device_id = resp.device_id;

    let challenge: ChallengeResponse = client
        .post_json("/v1/auth/challenge", &ChallengeRequest { device_id })
        .await
        .expect("gateway-test challenge must succeed");
    let verify: VerifyResponse = client
        .post_json(
            "/v1/auth/verify",
            &VerifyRequest {
                device_id,
                challenge: challenge.challenge.clone(),
                signature: Signature(
                    device_key.sign(&challenge_signing_input(device_id, &challenge.challenge)),
                ),
            },
        )
        .await
        .expect("gateway-test verify must succeed");
    TestDevice {
        device_id,
        token: verify.token,
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Open the gateway over plain ws:// with a bearer token on the upgrade
/// request (ADR-0005 §1: auth failure is a 401, no socket).
async fn gateway_connect(base_http: &str, token: &str) -> Ws {
    let ws_base = base_http.replacen("http://", "ws://", 1);
    let url = format!("{ws_base}/v1/gateway");
    let host = url
        .strip_prefix("ws://")
        .and_then(|rest| rest.split('/').next())
        .expect("gateway URL has a host")
        .to_string();
    let request = tungstenite::http::Request::builder()
        .uri(&url)
        .header("Host", &host)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .expect("build upgrade request");
    let stream = tokio::net::TcpStream::connect(&host)
        .await
        .expect("gateway TCP connect");
    let (ws, response) = tokio_tungstenite::client_async(request, stream)
        .await
        .expect("gateway upgrade must succeed for a valid token");
    assert_eq!(response.status(), 101);
    ws
}

/// Receive one server frame, failing loudly (never hanging) on timeout,
/// close, or a non-text/unparseable frame.
async fn recv_frame(ws: &mut Ws) -> GatewayServerFrame {
    let msg = tokio::time::timeout(FRAME_TIMEOUT, ws.next())
        .await
        .expect("timed out waiting for a gateway frame")
        .expect("gateway closed the socket unexpectedly")
        .expect("gateway frame transport error");
    let tungstenite::Message::Text(text) = msg else {
        panic!("expected a JSON text frame, got {msg:?}");
    };
    serde_json::from_str(&text).expect("gateway frame must be a GatewayServerFrame")
}

async fn send_frame(ws: &mut Ws, frame: &GatewayClientFrame) {
    let text = serde_json::to_string(frame).expect("client frame serializes");
    ws.send(tungstenite::Message::Text(text.into()))
        .await
        .expect("send client frame");
}

/// POST one message to a group (ADR-0005 §1). Payloads are opaque stand-in
/// ciphertext (see module docs).
async fn submit(
    client: &TestClient,
    token: &str,
    gid: GroupId,
    kind: EnvelopeKind,
    epoch: u64,
    payload: &[u8],
    recipients: Vec<DeviceId>,
) -> SubmitMessageResponse {
    let mut envelope = Envelope::new(kind, Some(gid), payload);
    envelope.epoch = Some(epoch);
    let req = SubmitMessageRequest {
        envelope,
        idempotency_key: uuid::Uuid::new_v4(),
        recipient_device_ids: recipients,
    };
    client
        .post_json_bearer(&format!("/v1/groups/{gid}/messages"), token, &req)
        .await
        .expect("submit must succeed on the live stack")
}

fn subscribe(gid: GroupId) -> GatewayClientFrame {
    GatewayClientFrame::Subscribe {
        group_ids: vec![gid],
    }
}

fn expect_message(frame: GatewayServerFrame, what: &str) -> Envelope {
    match frame {
        GatewayServerFrame::Message { envelope } => envelope,
        other => panic!("expected {what} as a Message frame, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn f2_gateway_welcome_delivery() {
    let http = probe_client().expect("harness probe client must build");
    let endpoints = require_stack(&http)
        .await
        .expect("compose stack must be up; CI provisions it before this test runs");
    let auth = TestClient::new(http.clone(), endpoints.auth.clone());
    let delivery = TestClient::new(http.clone(), endpoints.delivery.clone());

    let a = register_and_authenticate(&auth, 0xA0).await;
    let b = register_and_authenticate(&auth, 0xB0).await;
    let gid = GroupId::new();

    // A founds G by submitting the Welcome addressed to B's device (F2;
    // Amendment 1 §B: the first submit to a new gid MUST be a Welcome).
    let welcome = submit(
        &delivery,
        &a.token,
        gid,
        EnvelopeKind::Welcome,
        1,
        b"stand-in-mls-welcome-ciphertext",
        vec![b.device_id],
    )
    .await;
    assert_eq!(welcome.seq, 1, "the founding Welcome takes seq 1");
    assert_eq!(welcome.epoch, 1, "epoch is client-declared, echoed");

    // B's next gateway connect: the undelivered Welcome is pushed as a
    // Message frame with server-populated seq/sender, then marked
    // delivered (at-least-once; the client dedups).
    let mut ws_b = gateway_connect(&endpoints.delivery, &b.token).await;
    let env = expect_message(recv_frame(&mut ws_b).await, "the welcome push");
    assert_eq!(env.kind, EnvelopeKind::Welcome);
    assert_eq!(env.group_id, Some(gid));
    assert_eq!(env.seq, Some(1));
    assert_eq!(env.epoch, Some(1));
    assert_eq!(env.sender_device_id, Some(a.device_id));
    assert_eq!(
        env.payload_bytes().expect("payload is base64"),
        b"stand-in-mls-welcome-ciphertext"
    );

    // B is an addressee in G: Subscribe is acknowledged.
    send_frame(&mut ws_b, &subscribe(gid)).await;
    match recv_frame(&mut ws_b).await {
        GatewayServerFrame::Subscribed { group_ids } => assert_eq!(group_ids, vec![gid]),
        other => panic!("expected Subscribed, got {other:?}"),
    }

    // A posts an application message → live fanout to B, seq assigned,
    // epoch echoed (F4's wire shape, minus MLS).
    let app = submit(
        &delivery,
        &a.token,
        gid,
        EnvelopeKind::Application,
        1,
        b"stand-in-mls-app-ciphertext",
        vec![],
    )
    .await;
    assert_eq!(app.seq, 2);
    let env = expect_message(recv_frame(&mut ws_b).await, "the app-message fanout");
    assert_eq!(env.kind, EnvelopeKind::Application);
    assert_eq!(env.seq, Some(2));
    assert_eq!(env.epoch, Some(1));
    assert_eq!(env.sender_device_id, Some(a.device_id));
    assert_eq!(
        env.payload_bytes().expect("payload is base64"),
        b"stand-in-mls-app-ciphertext"
    );

    // Sync path (the catch-up channel the gateway hints at): B pages from
    // 0 and sees both rows, fully populated.
    let page: MessagesPage = delivery
        .get_json_bearer(&format!("/v1/groups/{gid}/messages?after=0"), &b.token)
        .await
        .expect("sync must succeed for any valid token");
    assert_eq!(page.messages.len(), 2);
    assert!(!page.has_more);
    assert_eq!(page.next_after, 2);
    assert_eq!(page.messages[0].kind, EnvelopeKind::Welcome);
    assert_eq!(page.messages[1].kind, EnvelopeKind::Application);

    // The pushed Welcome was marked delivered: a second connect pushes
    // nothing before we unsubscribe-quietly close.
    let mut ws_b2 = gateway_connect(&endpoints.delivery, &b.token).await;
    let nothing = tokio::time::timeout(Duration::from_millis(1500), ws_b2.next()).await;
    assert!(
        nothing.is_err(),
        "a delivered welcome must not be pushed again on reconnect"
    );
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn subscribe_rejects_non_addressee() {
    let http = probe_client().expect("harness probe client must build");
    let endpoints = require_stack(&http)
        .await
        .expect("compose stack must be up; CI provisions it before this test runs");
    let auth = TestClient::new(http.clone(), endpoints.auth.clone());
    let delivery = TestClient::new(http.clone(), endpoints.delivery.clone());

    let a = register_and_authenticate(&auth, 0xC0).await;
    let b = register_and_authenticate(&auth, 0xC2).await;
    let c = register_and_authenticate(&auth, 0xC4).await;
    let gid = GroupId::new();

    submit(
        &delivery,
        &a.token,
        gid,
        EnvelopeKind::Welcome,
        1,
        b"stand-in-mls-welcome-ciphertext",
        vec![b.device_id],
    )
    .await;

    // C has no delivery metadata in G (never a sender, not a welcome
    // recipient): Subscribe yields an Error frame per decision #5 and no
    // Subscribed ack.
    let mut ws_c = gateway_connect(&endpoints.delivery, &c.token).await;
    send_frame(&mut ws_c, &subscribe(gid)).await;
    match recv_frame(&mut ws_c).await {
        GatewayServerFrame::Error {
            code,
            group_id,
            message: _,
        } => {
            assert_eq!(code, ErrorCode::Forbidden);
            assert_eq!(group_id, Some(gid));
        }
        other => panic!("expected an Error frame for the non-addressee, got {other:?}"),
    }

    // A posts: C receives nothing for G (bounded wait — a hang here is a
    // pass only because the timeout bounds it; a frame is a loud failure).
    submit(
        &delivery,
        &a.token,
        gid,
        EnvelopeKind::Application,
        1,
        b"stand-in-mls-app-ciphertext-1",
        vec![],
    )
    .await;
    let eavesdropped = tokio::time::timeout(Duration::from_millis(1500), ws_c.next()).await;
    assert!(
        eavesdropped.is_err(),
        "non-addressee must receive no fanout for G"
    );

    // Positive arm (same test, so the subscription path can't silently
    // regress to reject-everyone): B connects, takes its welcome,
    // subscribes, and receives the next fanout.
    let mut ws_b = gateway_connect(&endpoints.delivery, &b.token).await;
    let welcome = expect_message(recv_frame(&mut ws_b).await, "B's welcome push");
    assert_eq!(welcome.kind, EnvelopeKind::Welcome);
    send_frame(&mut ws_b, &subscribe(gid)).await;
    match recv_frame(&mut ws_b).await {
        GatewayServerFrame::Subscribed { group_ids } => assert_eq!(group_ids, vec![gid]),
        other => panic!("expected Subscribed for the addressee, got {other:?}"),
    }
    submit(
        &delivery,
        &a.token,
        gid,
        EnvelopeKind::Application,
        1,
        b"stand-in-mls-app-ciphertext-2",
        vec![],
    )
    .await;
    let fanned = expect_message(recv_frame(&mut ws_b).await, "B's app-message fanout");
    assert_eq!(fanned.seq, Some(3));

    // Amendment 1 §B on the write path: C's REST submit to G is 403.
    let mut envelope = Envelope::new(EnvelopeKind::Application, Some(gid), b"stand-in");
    envelope.epoch = Some(1);
    let req = SubmitMessageRequest {
        envelope,
        idempotency_key: uuid::Uuid::new_v4(),
        recipient_device_ids: vec![],
    };
    let (status, err) = delivery
        .post_json_bearer_expect_error(&format!("/v1/groups/{gid}/messages"), &c.token, &req)
        .await
        .expect("a non-participant submit must be a wire error");
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert_eq!(err.code, ErrorCode::Forbidden);
}
