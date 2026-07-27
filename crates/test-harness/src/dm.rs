//! M2 DM test client: a REAL client driving citadel-core's actual MLS engine
//! against the live compose stack (F2 create/join, F4 send/receive).
//!
//! The harness never reimplements client logic: registration, challenge
//! auth, and KeyPackage publish/fetch go over the real HTTP contracts;
//! group operations go through [`citadel_core::group::DmGroup`]; membership
//! verification goes through [`LiveKtVerifier`], which attests ONLY what it
//! has cryptographically verified against the KT log (inclusion proof +
//! signed tree head under the pinned log anchor, `kt-log`).
//!
//! [`LiveKtVerifier`] note: `IdentityVerifier::is_kt_attested` is
//! synchronous (citadel-core's trait), but real KT verification is I/O. The
//! harness therefore splits it: [`LiveKtVerifier::attest`] does the real
//! asynchronous verification and records the outcome; the sync trait method
//! only reads the set of already-verified `(account, identity key)` pairs.
//! Nothing enters that set without a verified inclusion proof, so the sync
//! check is exactly "the log binds this account to this key" (INV-4).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use citadel_core::credential::IdentityVerifier;
use citadel_core::crypto::EphemeralProvider as Provider;
use citadel_core::group::{AddMembersOutput, DmGroup};
use citadel_core::identity::DeviceIdentity;
use citadel_proto::auth::{
    challenge_signing_input, ChallengeRequest, ChallengeResponse, FetchKeyPackagesResponse,
    KeyPackageBytes, PublishKeyPackagesRequest, PublishKeyPackagesResponse, RegisterAccountRequest,
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
use citadel_proto::ids::{AccountId, DeviceId, GroupId};
use citadel_proto::kt::{KtLeaf, KtProofResponse, SignedTreeHead};
use futures_util::{SinkExt, StreamExt};
use openmls::prelude::{KeyPackage, KeyPackageIn, ProtocolVersion};
use openmls_traits::OpenMlsProvider;
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};
use zeroize::Zeroizing;

use crate::client::TestClient;

/// The compose stack's pinned dev-only log seed (deploy/docker-compose.yml),
/// same anchor the M1 acceptance test pins. The harness is the client: it
/// holds the log public key as a pinned anchor (ADR-0001 §5) and never
/// accepts a key the server hands it.
const DEV_LOG_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The pinned KT log anchor (verifying key) for the stack under test.
pub fn log_anchor() -> [u8; 32] {
    let b64 = std::env::var("CITADEL_KT_LOG_SEED").unwrap_or_else(|_| DEV_LOG_SEED_B64.into());
    let seed = B64
        .decode(b64.trim())
        .expect("log anchor seed must be base64");
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .expect("log anchor seed must decode to 32 bytes");
    kt_log::TreeHeadSigner::from_seed(&seed).public_key()
}

/// What the harness knows about one account's KT leaf, learned from its own
/// registration response (never from the party being verified).
#[derive(Clone, Debug)]
pub struct LeafInfo {
    pub leaf_index: u64,
    pub handle: String,
    pub appended_at: i64,
}

/// A KT verifier that attests only what it has cryptographically verified
/// against the live log (see module docs for the async/sync split).
pub struct LiveKtVerifier {
    auth: TestClient,
    anchor: [u8; 32],
    leaves: HashMap<AccountId, LeafInfo>,
    /// `(account, identity key)` pairs with a verified inclusion proof.
    attested: Vec<(AccountId, [u8; 32])>,
}

impl LiveKtVerifier {
    pub fn new(auth: TestClient, anchor: [u8; 32]) -> Self {
        Self {
            auth,
            anchor,
            leaves: HashMap::new(),
            attested: Vec::new(),
        }
    }

    /// Record an account's leaf coordinates (from the harness's own
    /// registration of that account).
    pub fn register_leaf(&mut self, account_id: AccountId, info: LeafInfo) {
        self.leaves.insert(account_id, info);
    }

    /// The REAL verification (INV-4): fetch the latest signed tree head,
    /// verify it under the pinned anchor, fetch the account's inclusion
    /// proof at that tree size, rebuild the leaf with the EXACT identity key
    /// under test, and verify inclusion. Only a pass records the
    /// `(account, key)` pair as attested. Any failure — unknown account,
    /// unreachable log, bad head signature, proof mismatch — attests
    /// nothing and returns false.
    pub async fn attest(
        &mut self,
        account_id: AccountId,
        identity_pubkey: &IdentityPublicKey,
    ) -> bool {
        let Some(info) = self.leaves.get(&account_id) else {
            return false;
        };
        let Ok(latest) = self
            .auth
            .get_json::<SignedTreeHead>("/v1/kt/tree-head")
            .await
        else {
            return false;
        };
        if !kt_log::verify_tree_head(&latest, &self.anchor) {
            return false;
        }
        let Ok(pair) = self
            .auth
            .get_json::<KtProofResponse>(&format!(
                "/v1/kt/proof?leaf={}&tree_size={}",
                info.leaf_index, latest.tbs.tree_size
            ))
            .await
        else {
            return false;
        };
        if pair.signed_tree_head != latest {
            return false;
        }
        let leaf = KtLeaf {
            account_id,
            handle: info.handle.clone(),
            identity_pubkey: *identity_pubkey,
            appended_at: info.appended_at,
        };
        if !kt_log::verify_inclusion(&leaf, &pair.proof, &pair.signed_tree_head) {
            return false;
        }
        let pair = (account_id, identity_pubkey.0);
        if !self.attested.contains(&pair) {
            self.attested.push(pair);
        }
        true
    }
}

impl IdentityVerifier for LiveKtVerifier {
    fn is_kt_attested(&self, account_id: AccountId, identity_pubkey: &IdentityPublicKey) -> bool {
        self.attested.contains(&(account_id, identity_pubkey.0))
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// 32 bytes of OS-CSPRNG test key material (never production secrets).
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed
}

/// One fully provisioned client: registered account, first device,
/// authenticated, with a citadel-core identity and MLS provider.
pub struct DmClient {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub handle: String,
    pub token: String,
    pub identity_pubkey: IdentityPublicKey,
    pub provider: Provider,
    pub identity: DeviceIdentity,
    pub auth: TestClient,
    pub delivery: TestClient,
}

impl DmClient {
    /// Register a fresh account (first device) on the live stack and
    /// authenticate it (ADR-0003 §1–§2). `handle` must be unique per run —
    /// the compose DB persists across tests.
    pub async fn register(
        http: reqwest::Client,
        auth_base: &str,
        delivery_base: &str,
        handle: &str,
    ) -> Result<(Self, LeafInfo)> {
        let auth = TestClient::new(http.clone(), auth_base);
        let delivery = TestClient::new(http, delivery_base);

        let identity_seed = random_seed();
        let device_seed = random_seed();
        let identity_key = ed25519_dalek::SigningKey::from_bytes(&identity_seed);
        let device_key = ed25519_dalek::SigningKey::from_bytes(&device_seed);

        let identity_pubkey = IdentityPublicKey(identity_key.verifying_key().to_bytes());
        let tbs = DeviceCredentialTbs {
            account_id: AccountId::new(),
            device_id: DeviceId::new(),
            identity_pubkey,
            device_pubkey: DevicePublicKey(device_key.verifying_key().to_bytes()),
            issued_at: now_epoch(),
        };
        let signature =
            Signature(ed25519_dalek::Signer::sign(&identity_key, &tbs.signing_input()).to_bytes());
        let credential = DeviceCredential { tbs, signature };
        let resp: RegisterAccountResponse = auth
            .post_json(
                "/v1/accounts",
                &RegisterAccountRequest {
                    handle: handle.to_string(),
                    identity_pubkey,
                    first_device: credential.clone(),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("register {handle}: {e}"))?;

        // Challenge-response → bearer token (ADR-0003 §1–§2).
        let challenge: ChallengeResponse = auth
            .post_json(
                "/v1/auth/challenge",
                &ChallengeRequest {
                    device_id: resp.device_id,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("challenge {handle}: {e}"))?;
        let verify: VerifyResponse = auth
            .post_json(
                "/v1/auth/verify",
                &VerifyRequest {
                    device_id: resp.device_id,
                    challenge: challenge.challenge.clone(),
                    signature: Signature(
                        ed25519_dalek::Signer::sign(
                            &device_key,
                            &challenge_signing_input(resp.device_id, &challenge.challenge),
                        )
                        .to_bytes(),
                    ),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("verify {handle}: {e}"))?;

        let identity = DeviceIdentity::from_parts(
            credential,
            Zeroizing::new(device_seed),
            device_key.verifying_key().to_bytes(),
        )
        .context("build citadel-core identity from the registered credential")?;

        let leaf = LeafInfo {
            leaf_index: resp.kt_leaf_index,
            handle: handle.to_string(),
            appended_at: resp.kt_appended_at,
        };
        Ok((
            Self {
                account_id: resp.account_id,
                device_id: resp.device_id,
                handle: handle.to_string(),
                token: verify.token,
                identity_pubkey,
                provider: Provider::default(),
                identity,
                auth,
                delivery,
            },
            leaf,
        ))
    }

    /// Serialize one fresh KeyPackage for upload (the private init/encryption
    /// keys stay in this client's provider).
    pub fn new_key_package_bytes(&self) -> Result<Vec<u8>> {
        let kp = self
            .identity
            .new_key_package(&self.provider)
            .map_err(|e| anyhow::anyhow!("key package generation: {e}"))?;
        kp.tls_serialize_detached().context("serialize key package")
    }

    /// Publish `count` fresh KeyPackages to this device's pool (ADR-0003 §4).
    pub async fn publish_key_packages(&self, count: usize) -> Result<()> {
        let mut packages = Vec::with_capacity(count);
        for _ in 0..count {
            packages.push(KeyPackageBytes(self.new_key_package_bytes()?));
        }
        let resp: PublishKeyPackagesResponse = self
            .auth
            .post_json_bearer(
                &format!("/v1/devices/{}/key-packages", self.device_id),
                &self.token,
                &PublishKeyPackagesRequest { packages },
            )
            .await
            .map_err(|e| anyhow::anyhow!("publish key packages for {}: {e}", self.handle))?;
        if (resp.pool_size as usize) < count {
            bail!("pool_size {} below published count {count}", resp.pool_size);
        }
        Ok(())
    }

    /// Fetch and validate one KeyPackage per active device of `target`
    /// (consuming, all-or-nothing; ADR-0003 §4). `auth_base` defaults to the
    /// real auth-service; the adversarial suite passes a dishonest proxy —
    /// the bytes are UNTRUSTED either way, which is exactly why
    /// `DmGroup::add_members` verifies them (INV-4).
    pub async fn fetch_key_packages(
        &self,
        auth_base: &str,
        target: AccountId,
    ) -> Result<Vec<KeyPackage>> {
        let client = TestClient::new(reqwest::Client::new(), auth_base);
        let fetched: FetchKeyPackagesResponse = client
            .get_json_bearer(&format!("/v1/accounts/{target}/key-packages"), &self.token)
            .await
            .map_err(|e| anyhow::anyhow!("fetch key packages for {target}: {e}"))?;
        let mut out = Vec::with_capacity(fetched.packages.len());
        for pkg in fetched.packages {
            let kin = KeyPackageIn::tls_deserialize_exact_bytes(&pkg.package.0)
                .context("deserialize fetched key package")?;
            let kp = kin
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| anyhow::anyhow!("fetched key package fails MLS validation: {e}"))?;
            out.push(kp);
        }
        Ok(out)
    }

    /// Create the DM group (F2 step 1/2): this client is the initiator.
    pub fn create_group(&self, group_id: GroupId) -> Result<DmGroup> {
        DmGroup::create(&self.provider, &self.identity, group_id)
            .map_err(|e| anyhow::anyhow!("create group: {e}"))
    }

    /// Add fetched KeyPackages in one commit (F2 step 2). citadel-core
    /// verifies every credential against the KT log before any commit or
    /// Welcome exists (INV-4); a rejection propagates as an error here.
    pub fn add_members(
        &self,
        group: &mut DmGroup,
        key_packages: &[KeyPackage],
        verifier: &LiveKtVerifier,
    ) -> Result<AddMembersOutput> {
        group
            .add_members(&self.provider, &self.identity, key_packages, verifier)
            .map_err(|e| anyhow::anyhow!("add members: {e}"))
    }

    /// Join from a Welcome delivered by the DS (F2 step 3). citadel-core
    /// verifies every member credential against the KT log before accepting
    /// the group (INV-4).
    pub fn join_from_welcome(
        &self,
        welcome_bytes: &[u8],
        verifier: &LiveKtVerifier,
    ) -> Result<DmGroup> {
        DmGroup::join_from_welcome(&self.provider, welcome_bytes, verifier)
            .map_err(|e| anyhow::anyhow!("join from welcome: {e}"))
    }

    /// POST one envelope to the group (ADR-0005 §1). Returns the server
    /// assignment.
    pub async fn submit(
        &self,
        group_id: GroupId,
        kind: EnvelopeKind,
        epoch: u64,
        payload: &[u8],
        recipients: Vec<DeviceId>,
    ) -> Result<SubmitMessageResponse> {
        let mut envelope = Envelope::new(kind, Some(group_id), payload);
        envelope.epoch = Some(epoch);
        let req = SubmitMessageRequest {
            envelope,
            idempotency_key: uuid::Uuid::new_v4(),
            recipient_device_ids: recipients,
        };
        self.delivery
            .post_json_bearer(
                &format!("/v1/groups/{group_id}/messages"),
                &self.token,
                &req,
            )
            .await
            .map_err(|e| anyhow::anyhow!("submit {kind:?} to {group_id}: {e}"))
    }

    /// Encrypt and send an application message (F4 send): pad-then-encrypt
    /// inside citadel-core, submit the ciphertext.
    pub async fn send_text(
        &self,
        group: &mut DmGroup,
        group_id: GroupId,
        plaintext: &[u8],
    ) -> Result<SubmitMessageResponse> {
        let wire = group
            .send(&self.provider, &self.identity, plaintext)
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        self.submit(
            group_id,
            EnvelopeKind::Application,
            group.epoch(),
            &wire,
            vec![],
        )
        .await
    }

    /// One page of ciphertext sync (ADR-0005 §1; the cursor IS the seq).
    pub async fn sync(&self, group_id: GroupId, after: u64) -> Result<MessagesPage> {
        self.delivery
            .get_json_bearer(
                &format!("/v1/groups/{group_id}/messages?after={after}"),
                &self.token,
            )
            .await
            .map_err(|e| anyhow::anyhow!("sync {group_id} after {after}: {e}"))
    }

    /// Open the gateway with this device's token (plain ws:// on the
    /// compose stack; TLS termination is a deploy concern, M8).
    pub async fn gateway_connect(&self) -> Result<GatewaySocket> {
        gateway_connect(self.delivery.base(), &self.token).await
    }

    /// Process one synced envelope that has not been handled yet (offline
    /// catch-up): Welcomes are skipped when the group is already joined
    /// (the DS re-delivers until subscribe; the client dedups via MLS
    /// state). Returns the outcome for application/commit envelopes.
    pub fn process_envelope(
        &self,
        group: &mut DmGroup,
        envelope: &Envelope,
        verifier: &LiveKtVerifier,
    ) -> Result<Option<citadel_core::group::ReceiveOutcome>> {
        if envelope.kind == EnvelopeKind::Welcome {
            return Ok(None);
        }
        let bytes = envelope
            .payload_bytes()
            .context("decode envelope payload")?;
        let outcome = group
            .receive(&self.provider, &bytes, verifier)
            .map_err(|e| anyhow::anyhow!("process {:?}: {e}", envelope.kind))?;
        Ok(Some(outcome))
    }
}

/// An authenticated gateway WebSocket.
pub type GatewaySocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Open the gateway over plain ws:// with a bearer token on the upgrade
/// request (ADR-0005 §1: auth failure is a 401, no socket).
pub async fn gateway_connect(base_http: &str, token: &str) -> Result<GatewaySocket> {
    use tokio_tungstenite::tungstenite;
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
        .context("gateway TCP connect")?;
    let (ws, response) = tokio_tungstenite::client_async(request, stream)
        .await
        .context("gateway upgrade")?;
    if response.status() != 101 {
        bail!("gateway upgrade returned HTTP {}", response.status());
    }
    Ok(ws)
}

/// Receive one server frame, failing loudly (never hanging) on timeout,
/// close, or a non-text/unparseable frame.
pub async fn recv_frame(ws: &mut GatewaySocket) -> Result<GatewayServerFrame> {
    use tokio_tungstenite::tungstenite;
    let msg = tokio::time::timeout(FRAME_TIMEOUT, ws.next())
        .await
        .context("timed out waiting for a gateway frame")?
        .context("gateway closed the socket unexpectedly")?
        .context("gateway frame transport error")?;
    let tungstenite::Message::Text(text) = msg else {
        bail!("expected a JSON text frame, got {msg:?}");
    };
    serde_json::from_str(&text).context("gateway frame must be a GatewayServerFrame")
}

pub async fn send_frame(ws: &mut GatewaySocket, frame: &GatewayClientFrame) -> Result<()> {
    use tokio_tungstenite::tungstenite;
    let text = serde_json::to_string(frame).context("client frame serializes")?;
    ws.send(tungstenite::Message::Text(text.into()))
        .await
        .context("send client frame")
}

/// Receive frames until a `Message` envelope for `group_id` of the wanted
/// kind arrives (bounded). Other frames (e.g. re-pushed Welcomes) are
/// skipped.
pub async fn recv_message_for(
    ws: &mut GatewaySocket,
    group_id: GroupId,
    kind: EnvelopeKind,
) -> Result<Envelope> {
    for _ in 0..8 {
        match recv_frame(ws).await? {
            GatewayServerFrame::Message { envelope }
                if envelope.group_id == Some(group_id) && envelope.kind == kind =>
            {
                return Ok(envelope)
            }
            _ => continue,
        }
    }
    bail!("no {kind:?} message for {group_id} arrived within the frame bound")
}

/// [`recv_message_for`] that also skips envelopes sent by the caller's own
/// device. A subscribed sender receives its OWN submissions back over
/// fanout; the client already holds that plaintext, and OpenMLS refuses to
/// decrypt a client's own messages (`CannotDecryptOwnMessage`) — so fanout
/// reads always filter the reader's own device.
pub async fn recv_foreign_message_for(
    ws: &mut GatewaySocket,
    group_id: GroupId,
    kind: EnvelopeKind,
    own_device: DeviceId,
) -> Result<Envelope> {
    for _ in 0..8 {
        let envelope = recv_message_for(ws, group_id, kind).await?;
        if envelope.sender_device_id == Some(own_device) {
            continue;
        }
        return Ok(envelope);
    }
    bail!("no foreign {kind:?} message for {group_id} arrived within the bound")
}
