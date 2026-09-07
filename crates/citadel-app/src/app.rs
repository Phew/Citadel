//! The session state machine and the two loops.

use crate::error::AppError;
use crate::kt::KtVerifier;
use crate::transport::{AuthApi, DeliveryApi, Gateway, HttpClient};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use citadel_core::credential::IdentityVerifier as _;
use citadel_core::identity::DeviceIdentity;
use citadel_core::store::{
    CredentialStore, LocalStore, OperationId, OperationOutcome, ProfilePaths, ProfileRow,
    SecretItem,
};
use citadel_proto::auth::{
    challenge_signing_input, KeyPackageBytes, PublishKeyPackagesRequest, RegisterAccountRequest,
    VerifyRequest,
};
use citadel_proto::credential::{
    DeviceCredential, DeviceCredentialTbs, DevicePublicKey, IdentityPublicKey, Signature,
};
use citadel_proto::delivery::{GatewayClientFrame, GatewayServerFrame, SubmitMessageRequest};
use citadel_proto::envelope::{Envelope, EnvelopeKind};
use citadel_proto::ids::{AccountId, DeviceId, GroupId};
use citadel_proto::kt::KtLeafInfo;
use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::{KeyPackage, KeyPackageIn, ProtocolVersion};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};
use tokio::sync::{broadcast, Notify};
use zeroize::Zeroizing;

/// Where the services are and which log to trust.
#[derive(Clone, Debug)]
pub struct Config {
    pub auth_base: String,
    pub delivery_base: String,
    /// The KT log's Ed25519 public key, embedded at build time in a shipped
    /// client (docs/protocol/auth.md: never fetched).
    pub kt_anchor: [u8; 32],
}

impl Config {
    /// The local compose stack. Reads `CITADEL_AUTH_URL`, `CITADEL_DELIVERY_URL`
    /// and `CITADEL_KT_LOG_SEED` (the dev seed when unset, matching
    /// `.env.example`), deriving the anchor from the seed.
    pub fn dev() -> Self {
        const DEV_LOG_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let seed_b64 =
            std::env::var("CITADEL_KT_LOG_SEED").unwrap_or_else(|_| DEV_LOG_SEED_B64.into());
        let seed: [u8; 32] = B64
            .decode(seed_b64.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("CITADEL_KT_LOG_SEED must be base64 of 32 bytes");
        Self {
            auth_base: std::env::var("CITADEL_AUTH_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8081".into()),
            delivery_base: std::env::var("CITADEL_DELIVERY_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8082".into()),
            kt_anchor: kt_log::TreeHeadSigner::from_seed(&seed).public_key(),
        }
    }
}

/// What a host renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub handle: String,
    pub identity_pubkey: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub group_id: GroupId,
    pub title: Option<String>,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: i64,
    pub group_id: GroupId,
    pub outgoing: bool,
    pub epoch: u64,
    pub plaintext: Vec<u8>,
}

/// Pushed to hosts as things happen.
#[derive(Clone, Debug)]
pub enum AppEvent {
    Registered(Profile),
    LoggedIn,
    ConversationCreated(GroupId),
    ConversationJoined(GroupId),
    MessageSent {
        group_id: GroupId,
    },
    MessageReceived {
        group_id: GroupId,
        epoch: u64,
        plaintext: Vec<u8>,
    },
    EpochAdvanced {
        group_id: GroupId,
        epoch: u64,
    },
    GatewayConnected,
    GatewayDisconnected,
    /// A non-fatal problem the host should show.
    Warning(String),
}

struct Session {
    token: String,
    identity: Arc<DeviceIdentity>,
    profile: Profile,
}

/// The app core. One per profile; hold it in an `Arc`.
pub struct CitadelApp {
    config: Config,
    store: Arc<LocalStore>,
    credentials: Arc<dyn CredentialStore>,
    auth: AuthApi,
    delivery: DeliveryApi,
    verifier: Arc<KtVerifier>,
    session: Mutex<Option<Arc<Session>>>,
    events: broadcast::Sender<AppEvent>,
    resubscribe: Notify,
}

const KEY_PACKAGE_BATCH: usize = 20;

impl CitadelApp {
    /// Open (or create) the profile at `paths`. No network.
    pub fn open(
        config: Config,
        paths: ProfilePaths,
        credentials: Arc<dyn CredentialStore>,
    ) -> Result<Arc<Self>, AppError> {
        let store = Arc::new(LocalStore::open(paths, credentials.clone())?);
        let http = reqwest::Client::builder()
            .build()
            .map_err(AppError::transport)?;
        let auth = AuthApi(HttpClient::new(http.clone(), &config.auth_base));
        let delivery = DeliveryApi(HttpClient::new(http, &config.delivery_base));
        let verifier = Arc::new(KtVerifier::new(
            auth.clone(),
            config.kt_anchor,
            store.clone(),
        )?);
        let (events, _) = broadcast::channel(256);
        Ok(Arc::new(Self {
            config,
            store,
            credentials,
            auth,
            delivery,
            verifier,
            session: Mutex::new(None),
            events,
            resubscribe: Notify::new(),
        }))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn store(&self) -> &Arc<LocalStore> {
        &self.store
    }

    pub fn verifier(&self) -> &Arc<KtVerifier> {
        &self.verifier
    }

    pub fn events(&self) -> broadcast::Receiver<AppEvent> {
        self.events.subscribe()
    }

    fn emit(&self, event: AppEvent) {
        let _ = self.events.send(event);
    }

    /// The registered profile, if any (no network).
    pub fn profile(&self) -> Result<Option<Profile>, AppError> {
        Ok(self.store.profile()?.map(|row| Profile {
            account_id: row.account_id,
            device_id: row.device_id,
            handle: row.handle,
            identity_pubkey: row.identity_pubkey,
        }))
    }

    fn session(&self) -> Result<Arc<Session>, AppError> {
        self.session
            .lock()
            .expect("session lock poisoned")
            .clone()
            .ok_or(AppError::NotLoggedIn)
    }

    // ---------------------------------------------------------------- F1

    /// Register a new account with this device as its first device, verify
    /// our own KT inclusion, log in, and publish a first KeyPackage batch.
    pub async fn register(&self, handle: &str) -> Result<Profile, AppError> {
        if self.store.profile()?.is_some() {
            return Err(AppError::AlreadyRegistered);
        }
        // Two independent seeds from the OS CSPRNG through the provider (INV-9).
        let rand = RustCrypto::default();
        let identity_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            rand.random_array()
                .map_err(|e| AppError::Mls(format!("csprng: {e:?}")))?,
        );
        let device_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            rand.random_array()
                .map_err(|e| AppError::Mls(format!("csprng: {e:?}")))?,
        );
        let identity_key = SigningKey::from_bytes(&identity_seed);
        let device_key = SigningKey::from_bytes(&device_seed);
        let identity_pubkey = IdentityPublicKey(identity_key.verifying_key().to_bytes());
        let device_pubkey = DevicePublicKey(device_key.verifying_key().to_bytes());

        let tbs = DeviceCredentialTbs {
            account_id: AccountId::new(),
            device_id: DeviceId::new(),
            identity_pubkey,
            device_pubkey,
            issued_at: now_unix(),
        };
        let signature = Signature(identity_key.sign(&tbs.signing_input()).to_bytes());
        let credential = DeviceCredential { tbs, signature };

        // Seeds go to the credential store BEFORE the network call: if the
        // server registers us and the response is lost, the seeds that own
        // that account still exist here.
        self.credentials
            .write(SecretItem::AccountIdentitySigningSeed, &identity_seed)?;
        self.credentials
            .write(SecretItem::DeviceSigningSeed, &device_seed)?;

        let response = self
            .auth
            .register(&RegisterAccountRequest {
                handle: handle.to_string(),
                identity_pubkey,
                first_device: credential.clone(),
            })
            .await?;

        // Our own inclusion, verified under the head the server signed at
        // registration and checkpointed (docs/protocol/auth.md).
        let head = self.verifier.accept_head(response.kt_tree_head).await?;
        let own = KtLeafInfo {
            account_id: response.account_id,
            handle: handle.to_string(),
            identity_pubkey,
            leaf_index: response.kt_leaf_index,
            appended_at: response.kt_appended_at,
        };
        self.verifier.attest_under(&own, &head).await?;

        self.store.set_profile(ProfileRow {
            account_id: response.account_id,
            device_id: response.device_id,
            handle: handle.to_string(),
            identity_pubkey: identity_pubkey.0,
            device_pubkey: device_pubkey.0,
            credential,
            kt_leaf_index: response.kt_leaf_index,
            kt_appended_at: response.kt_appended_at,
        })?;

        let profile = self.login().await?;
        self.publish_key_packages(KEY_PACKAGE_BATCH).await?;
        self.emit(AppEvent::Registered(profile.clone()));
        Ok(profile)
    }

    /// Challenge-response login with the device seed. Required once per
    /// process; tokens are not persisted.
    pub async fn login(&self) -> Result<Profile, AppError> {
        let row = self.store.profile()?.ok_or(AppError::NoProfile)?;
        let device_seed = self
            .credentials
            .read(SecretItem::DeviceSigningSeed)?
            .ok_or_else(|| {
                AppError::Credentials(citadel_core::store::CredentialStoreError::Backend(
                    "the device signing seed is absent for a registered profile".into(),
                ))
            })?;
        let device_key = SigningKey::from_bytes(&device_seed);
        if device_key.verifying_key().to_bytes() != row.device_pubkey {
            return Err(AppError::Identity(
                citadel_core::identity::IdentityError::SuppliedPublicKeyMismatch,
            ));
        }
        let challenge = self.auth.challenge(row.device_id).await?;
        let verify = self
            .auth
            .verify(&VerifyRequest {
                device_id: row.device_id,
                challenge: challenge.challenge.clone(),
                signature: Signature(
                    device_key
                        .sign(&challenge_signing_input(
                            row.device_id,
                            &challenge.challenge,
                        ))
                        .to_bytes(),
                ),
            })
            .await?;
        let identity =
            DeviceIdentity::from_parts(row.credential.clone(), device_seed, row.device_pubkey)?;
        let profile = Profile {
            account_id: row.account_id,
            device_id: row.device_id,
            handle: row.handle,
            identity_pubkey: row.identity_pubkey,
        };
        *self.session.lock().expect("session lock poisoned") = Some(Arc::new(Session {
            token: verify.token,
            identity: Arc::new(identity),
            profile: profile.clone(),
        }));
        self.emit(AppEvent::LoggedIn);
        Ok(profile)
    }

    /// Generate `count` KeyPackages in the store (their private keys persist
    /// there) and publish them to the one-time pool.
    pub async fn publish_key_packages(&self, count: usize) -> Result<u32, AppError> {
        let session = self.session()?;
        let mut packages = Vec::with_capacity(count);
        for _ in 0..count {
            let package = self.store.new_key_package(session.identity.clone())?;
            let bytes = package
                .tls_serialize_detached()
                .map_err(|e| AppError::Mls(format!("serialize key package: {e}")))?;
            packages.push(KeyPackageBytes(bytes));
        }
        let response = self
            .auth
            .publish_key_packages(
                &session.token,
                session.profile.device_id,
                &PublishKeyPackagesRequest { packages },
            )
            .await?;
        Ok(response.pool_size)
    }

    // ---------------------------------------------------------------- F2

    /// Resolve and KT-verify a peer by handle.
    pub async fn lookup(&self, handle: &str) -> Result<KtLeafInfo, AppError> {
        self.verifier.lookup_handle(handle).await
    }

    /// Create a DM with KT-verified peers (by account id). Fetches one
    /// KeyPackage per device of each peer, creates the group, adds them in one
    /// commit, and submits the commit and the Welcome.
    pub async fn create_dm(
        &self,
        peers: &[AccountId],
        title: Option<String>,
    ) -> Result<GroupId, AppError> {
        let session = self.session()?;
        let mut key_packages = Vec::new();
        let mut recipients = Vec::new();
        for account in peers {
            self.verifier.lookup_account(*account).await?;
            let fetched = self
                .auth
                .fetch_key_packages(&session.token, *account)
                .await?;
            if fetched.packages.is_empty() {
                return Err(AppError::NoKeyPackage(*account));
            }
            for package in fetched.packages {
                let package_in = KeyPackageIn::tls_deserialize_exact_bytes(&package.package.0)
                    .map_err(|e| AppError::Mls(format!("key package for {account}: {e}")))?;
                let validated: KeyPackage = package_in
                    .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
                    .map_err(|e| AppError::Mls(format!("key package for {account}: {e}")))?;
                key_packages.push(validated);
                recipients.push(package.device_id);
            }
        }

        let group_id = GroupId::new();
        self.store.create_group(
            OperationId::generate()?,
            session.identity.clone(),
            group_id,
            title,
        )?;
        self.store.add_members(
            OperationId::generate()?,
            session.identity.clone(),
            group_id,
            key_packages,
            recipients,
            self.verifier.clone(),
        )?;
        self.emit(AppEvent::ConversationCreated(group_id));
        self.resubscribe.notify_one();
        self.flush_outbox().await?;
        Ok(group_id)
    }

    // ---------------------------------------------------------------- F4

    pub async fn send(&self, group_id: GroupId, plaintext: &[u8]) -> Result<(), AppError> {
        let session = self.session()?;
        self.store.send(
            OperationId::generate()?,
            session.identity.clone(),
            group_id,
            plaintext.to_vec(),
        )?;
        self.flush_outbox().await?;
        self.emit(AppEvent::MessageSent { group_id });
        Ok(())
    }

    /// Submit every pending transmission under its stored idempotency key and
    /// acknowledge each on terminal acceptance. A rejection is terminal too
    /// (the bytes will never be accepted); a transport failure stops the
    /// flush so the rest is retried later.
    pub async fn flush_outbox(&self) -> Result<usize, AppError> {
        let session = self.session()?;
        let mut flushed = 0;
        for pending in self.store.pending_transmissions()? {
            let kind = match pending.kind.as_str() {
                "application" => EnvelopeKind::Application,
                "commit" => EnvelopeKind::Commit,
                "welcome" => EnvelopeKind::Welcome,
                other => {
                    return Err(AppError::Store(
                        citadel_core::store::StoreError::StoreStateInconsistent(Box::leak(
                            format!("unknown pending kind {other}").into_boxed_str(),
                        )),
                    ))
                }
            };
            let epoch = pending
                .proposed_epoch
                .unwrap_or(self.store.group_epoch(pending.group_id)?);
            let mut envelope = Envelope::new(kind, Some(pending.group_id), &pending.wire_bytes);
            envelope.epoch = Some(epoch);
            let request = SubmitMessageRequest {
                envelope,
                idempotency_key: uuid::Uuid::from_bytes(pending.idempotency_key),
                recipient_device_ids: pending.recipient_device_ids.clone(),
            };
            match self.delivery.submit(&session.token, &request).await {
                Ok(response) => {
                    self.store
                        .acknowledge_transmission(pending.idempotency_key)?;
                    // Our own message is fanned out to us too; the cursor
                    // moves past it so sync never hands it back to OpenMLS.
                    self.store
                        .set_delivery_cursor(pending.group_id, response.seq)?;
                    flushed += 1;
                }
                Err(AppError::Rejected {
                    status,
                    code,
                    message,
                }) => {
                    self.store
                        .acknowledge_transmission(pending.idempotency_key)?;
                    self.emit(AppEvent::Warning(format!(
                        "delivery rejected a pending {kind:?} for {} (HTTP {status}, {code:?}): {message}",
                        pending.group_id
                    )));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(flushed)
    }

    /// Pull every conversation up to date over REST, in sequence order.
    pub async fn sync(&self) -> Result<(), AppError> {
        for conversation in self.store.conversations()? {
            self.sync_group(conversation.group_id).await?;
        }
        Ok(())
    }

    pub async fn sync_group(&self, group_id: GroupId) -> Result<(), AppError> {
        let session = self.session()?;
        loop {
            let after = self.store.delivery_cursor(group_id)?;
            let page = self.delivery.fetch(&session.token, group_id, after).await?;
            for envelope in &page.messages {
                self.process_envelope(envelope).await?;
            }
            if !page.has_more {
                return Ok(());
            }
        }
    }

    /// One envelope from the gateway or a sync page: version check first
    /// (INV-5), then the store, then the cursor.
    async fn process_envelope(&self, envelope: &Envelope) -> Result<(), AppError> {
        if !envelope.version_supported() {
            return Err(AppError::UnsupportedWireVersion(envelope.version));
        }
        let session = self.session()?;
        let group_id = envelope
            .group_id
            .ok_or_else(|| AppError::MalformedEnvelope("envelope without a group id".into()))?;
        let seq = envelope
            .seq
            .ok_or_else(|| AppError::MalformedEnvelope("delivered envelope without seq".into()))?;
        let bytes = envelope
            .payload_bytes()
            .map_err(|e| AppError::MalformedEnvelope(format!("payload base64: {e}")))?;

        let own = envelope.sender_device_id == Some(session.profile.device_id);
        match envelope.kind {
            EnvelopeKind::Welcome => {
                if !own {
                    let known = self
                        .store
                        .conversations()?
                        .iter()
                        .any(|c| c.group_id == group_id);
                    if !known {
                        // INV-4: attest every member we do not already know
                        // BEFORE the join re-verifies them all.
                        for member in self.store.welcome_members(bytes.clone())? {
                            let account = member.tbs.account_id;
                            if account == session.profile.account_id
                                || self
                                    .verifier
                                    .is_kt_attested(account, &member.tbs.identity_pubkey)
                            {
                                continue;
                            }
                            self.verifier.lookup_account(account).await?;
                        }
                        self.store.join_from_welcome(
                            OperationId::generate()?,
                            group_id,
                            bytes,
                            self.verifier.clone(),
                            None,
                        )?;
                        self.store.set_delivery_cursor(group_id, seq)?;
                        self.emit(AppEvent::ConversationJoined(group_id));
                        self.resubscribe.notify_one();
                        return Ok(());
                    }
                }
            }
            EnvelopeKind::Application | EnvelopeKind::Commit => {
                if !own {
                    let outcome = self.store.receive(
                        OperationId::generate()?,
                        group_id,
                        bytes,
                        self.verifier.clone(),
                    )?;
                    match outcome {
                        OperationOutcome::ReceivedApplication {
                            plaintext,
                            deduplicated: false,
                        } => {
                            let epoch = self.store.group_epoch(group_id)?;
                            self.emit(AppEvent::MessageReceived {
                                group_id,
                                epoch,
                                plaintext,
                            });
                        }
                        OperationOutcome::CommitMerged { epoch } => {
                            self.emit(AppEvent::EpochAdvanced { group_id, epoch });
                        }
                        _ => {}
                    }
                }
            }
            EnvelopeKind::Proposal | EnvelopeKind::Control => {
                self.emit(AppEvent::Warning(format!(
                    "ignoring a {:?} envelope for {group_id} (M3)",
                    envelope.kind
                )));
            }
        }
        self.store.set_delivery_cursor(group_id, seq)?;
        Ok(())
    }

    /// Hold a gateway connection until it drops: Welcomes arrive here on
    /// connect, live fanout after subscribing. Out-of-order frames trigger a
    /// sync of that group so the store only ever sees sequence order.
    pub async fn run_gateway(&self) -> Result<(), AppError> {
        let session = self.session()?;
        let mut gateway: Gateway = self.delivery.gateway(&session.token).await?;
        self.emit(AppEvent::GatewayConnected);
        let mut subscribed: HashSet<GroupId> = HashSet::new();
        self.subscribe_missing(&mut gateway, &mut subscribed)
            .await?;
        let result = loop {
            tokio::select! {
                frame = gateway.next() => match frame {
                    Ok(GatewayServerFrame::Message { envelope }) => {
                        if let Err(error) = self.on_gateway_envelope(&envelope).await {
                            self.emit(AppEvent::Warning(format!("gateway envelope: {error}")));
                        }
                    }
                    Ok(GatewayServerFrame::Subscribed { .. }) => {}
                    Ok(GatewayServerFrame::Error { code, message, group_id }) => {
                        self.emit(AppEvent::Warning(format!(
                            "gateway error {code:?} for {group_id:?}: {message}"
                        )));
                    }
                    Err(error) => break Err(error),
                },
                _ = self.resubscribe.notified() => {
                    if let Err(error) = self.subscribe_missing(&mut gateway, &mut subscribed).await {
                        break Err(error);
                    }
                }
            }
        };
        self.emit(AppEvent::GatewayDisconnected);
        result
    }

    async fn subscribe_missing(
        &self,
        gateway: &mut Gateway,
        subscribed: &mut HashSet<GroupId>,
    ) -> Result<(), AppError> {
        let missing: Vec<GroupId> = self
            .store
            .conversations()?
            .into_iter()
            .map(|c| c.group_id)
            .filter(|g| !subscribed.contains(g))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        gateway
            .send(&GatewayClientFrame::Subscribe {
                group_ids: missing.clone(),
            })
            .await?;
        subscribed.extend(missing.iter().copied());
        // Anything that arrived between the last cursor and now.
        for group_id in missing {
            self.sync_group(group_id).await?;
        }
        Ok(())
    }

    async fn on_gateway_envelope(&self, envelope: &Envelope) -> Result<(), AppError> {
        let group_id = envelope
            .group_id
            .ok_or_else(|| AppError::MalformedEnvelope("envelope without a group id".into()))?;
        let seq = envelope
            .seq
            .ok_or_else(|| AppError::MalformedEnvelope("delivered envelope without seq".into()))?;
        if envelope.kind == EnvelopeKind::Welcome {
            return self.process_envelope(envelope).await;
        }
        let cursor = self.store.delivery_cursor(group_id)?;
        if seq <= cursor {
            return Ok(());
        }
        if seq == cursor + 1 {
            self.process_envelope(envelope).await
        } else {
            // A gap: pull the page so nothing is applied out of order.
            self.sync_group(group_id).await
        }
    }

    // ---------------------------------------------------------------- reads

    pub fn conversations(&self) -> Result<Vec<Conversation>, AppError> {
        Ok(self
            .store
            .conversations()?
            .into_iter()
            .map(|row| Conversation {
                group_id: row.group_id,
                title: row.title,
                epoch: row.last_epoch,
            })
            .collect())
    }

    pub fn messages(&self, group_id: GroupId) -> Result<Vec<Message>, AppError> {
        Ok(self
            .store
            .messages(group_id)?
            .into_iter()
            .map(|row| Message {
                id: row.id,
                group_id: row.group_id,
                outgoing: row.direction == "outgoing",
                epoch: row.epoch,
                plaintext: row.plaintext,
            })
            .collect())
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
