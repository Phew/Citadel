//! The UniFFI surface for native hosts.
//!
//! Every method is blocking and runs on an internal tokio runtime; hosts call
//! them off the UI thread (a Swift `Task`, a Kotlin coroutine on `IO`). The
//! gateway runs as a background task inside this library and reports through
//! the host's [`EventListener`]. Hosts render; they make no trust decision:
//! every KT verification and every wire-version check happens below this
//! line, in `citadel-app` and `citadel-core`.
//!
//! Ids cross the boundary as UUID strings and message content as UTF-8 text
//! (lossy for non-UTF-8 payloads, which no current sender produces).

use citadel_app::{AppEvent, CitadelApp, Config};
use citadel_core::store::{CredentialStore, NativeCredentialStore, ProfilePaths};
use citadel_proto::ids::{AccountId, GroupId};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CitadelError {
    #[error("{0}")]
    Failed(String),
}

impl From<citadel_app::AppError> for CitadelError {
    fn from(error: citadel_app::AppError) -> Self {
        CitadelError::Failed(error.to_string())
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Profile {
    pub account_id: String,
    pub device_id: String,
    pub handle: String,
    pub identity_pubkey_hex: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Peer {
    pub account_id: String,
    pub handle: String,
    pub identity_pubkey_hex: String,
    pub kt_leaf_index: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Conversation {
    pub group_id: String,
    pub title: Option<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    pub id: i64,
    pub group_id: String,
    pub outgoing: bool,
    pub epoch: u64,
    pub text: String,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Event {
    Registered {
        profile: Profile,
    },
    LoggedIn,
    ConversationCreated {
        group_id: String,
    },
    ConversationJoined {
        group_id: String,
    },
    MessageSent {
        group_id: String,
    },
    MessageReceived {
        group_id: String,
        epoch: u64,
        text: String,
    },
    EpochAdvanced {
        group_id: String,
        epoch: u64,
    },
    GatewayConnected,
    GatewayDisconnected,
    Warning {
        text: String,
    },
}

/// Implemented by the host. Called from a background thread.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: Event);
}

/// One profile. Hold one per signed-in account.
#[derive(uniffi::Object)]
pub struct Client {
    runtime: Runtime,
    app: Arc<CitadelApp>,
    gateway: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl Client {
    /// Open (or create) the profile at `profile_root`. `credential_service`
    /// names the OS credential-store entries (use one per profile);
    /// `auth_url`/`delivery_url` are the service bases; `kt_anchor_hex` is
    /// the log's Ed25519 public key (64 hex chars) — a shipped host embeds it.
    #[uniffi::constructor]
    pub fn open(
        profile_root: String,
        credential_service: String,
        auth_url: String,
        delivery_url: String,
        kt_anchor_hex: String,
    ) -> Result<Arc<Self>, CitadelError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| CitadelError::Failed(format!("runtime: {e}")))?;
        let kt_anchor = parse_hex32(&kt_anchor_hex)?;
        let config = Config {
            auth_base: auth_url,
            delivery_base: delivery_url,
            kt_anchor,
        };
        let credentials: Arc<dyn CredentialStore> =
            Arc::new(NativeCredentialStore::with_service(credential_service));
        let app = CitadelApp::open(config, ProfilePaths::at_root(profile_root), credentials)?;
        Ok(Arc::new(Self {
            runtime,
            app,
            gateway: Mutex::new(None),
        }))
    }

    /// The dev stack's log anchor, derived from the public dev seed. Never
    /// use in a shipped host.
    #[uniffi::constructor]
    pub fn open_dev(
        profile_root: String,
        credential_service: String,
    ) -> Result<Arc<Self>, CitadelError> {
        let dev = Config::dev();
        Self::open(
            profile_root,
            credential_service,
            dev.auth_base,
            dev.delivery_base,
            hex(&dev.kt_anchor),
        )
    }

    pub fn profile(&self) -> Result<Option<Profile>, CitadelError> {
        Ok(self.app.profile()?.map(profile_out))
    }

    pub fn register(&self, handle: String) -> Result<Profile, CitadelError> {
        let app = self.app.clone();
        self.runtime
            .block_on(async move { app.register(&handle).await })
            .map(profile_out)
            .map_err(Into::into)
    }

    pub fn login(&self) -> Result<Profile, CitadelError> {
        let app = self.app.clone();
        self.runtime
            .block_on(async move { app.login().await })
            .map(profile_out)
            .map_err(Into::into)
    }

    /// KT-verify a peer by handle.
    pub fn lookup(&self, handle: String) -> Result<Peer, CitadelError> {
        let app = self.app.clone();
        let info = self
            .runtime
            .block_on(async move { app.lookup(&handle).await })?;
        Ok(Peer {
            account_id: info.account_id.to_string(),
            handle: info.handle,
            identity_pubkey_hex: hex(&info.identity_pubkey.0),
            kt_leaf_index: info.leaf_index,
        })
    }

    /// Open a DM with KT-verified peers (handles). Returns the group id.
    pub fn create_dm(
        &self,
        handles: Vec<String>,
        title: Option<String>,
    ) -> Result<String, CitadelError> {
        let app = self.app.clone();
        let group_id = self.runtime.block_on(async move {
            let mut accounts: Vec<AccountId> = Vec::with_capacity(handles.len());
            for handle in &handles {
                accounts.push(app.lookup(handle).await?.account_id);
            }
            app.create_dm(&accounts, title).await
        })?;
        Ok(group_id.to_string())
    }

    pub fn send(&self, group_id: String, text: String) -> Result<(), CitadelError> {
        let group_id = parse_group(&group_id)?;
        let app = self.app.clone();
        self.runtime
            .block_on(async move { app.send(group_id, text.as_bytes()).await })
            .map_err(Into::into)
    }

    pub fn sync(&self) -> Result<(), CitadelError> {
        let app = self.app.clone();
        self.runtime
            .block_on(async move { app.sync().await })
            .map_err(Into::into)
    }

    pub fn conversations(&self) -> Result<Vec<Conversation>, CitadelError> {
        Ok(self
            .app
            .conversations()?
            .into_iter()
            .map(|c| Conversation {
                group_id: c.group_id.to_string(),
                title: c.title,
                epoch: c.epoch,
            })
            .collect())
    }

    pub fn messages(&self, group_id: String) -> Result<Vec<Message>, CitadelError> {
        let group_id = parse_group(&group_id)?;
        Ok(self
            .app
            .messages(group_id)?
            .into_iter()
            .map(|m| Message {
                id: m.id,
                group_id: m.group_id.to_string(),
                outgoing: m.outgoing,
                epoch: m.epoch,
                text: String::from_utf8_lossy(&m.plaintext).into_owned(),
            })
            .collect())
    }

    /// Hold the gateway open in the background (reconnecting) and forward
    /// every event to `listener`. Requires a login. Idempotent.
    pub fn start_gateway(&self, listener: Box<dyn EventListener>) {
        let mut slot = self.gateway.lock().expect("gateway slot poisoned");
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let app = self.app.clone();
        let listener: Arc<dyn EventListener> = Arc::from(listener);
        let mut events = app.events();
        let forwarder = {
            let listener = listener.clone();
            self.runtime.spawn(async move {
                while let Ok(event) = events.recv().await {
                    listener.on_event(event_out(event));
                }
            })
        };
        let handle = self.runtime.spawn(async move {
            loop {
                match app.run_gateway().await {
                    Ok(()) => break,
                    Err(error) => {
                        listener.on_event(Event::Warning {
                            text: format!("gateway: {error}; reconnecting"),
                        });
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
            }
            forwarder.abort();
        });
        *slot = Some(handle);
    }

    pub fn stop_gateway(&self) {
        if let Some(handle) = self.gateway.lock().expect("gateway slot poisoned").take() {
            handle.abort();
        }
    }
}

fn profile_out(p: citadel_app::Profile) -> Profile {
    Profile {
        account_id: p.account_id.to_string(),
        device_id: p.device_id.to_string(),
        handle: p.handle,
        identity_pubkey_hex: hex(&p.identity_pubkey),
    }
}

fn event_out(event: AppEvent) -> Event {
    match event {
        AppEvent::Registered(p) => Event::Registered {
            profile: profile_out(p),
        },
        AppEvent::LoggedIn => Event::LoggedIn,
        AppEvent::ConversationCreated(g) => Event::ConversationCreated {
            group_id: g.to_string(),
        },
        AppEvent::ConversationJoined(g) => Event::ConversationJoined {
            group_id: g.to_string(),
        },
        AppEvent::MessageSent { group_id } => Event::MessageSent {
            group_id: group_id.to_string(),
        },
        AppEvent::MessageReceived {
            group_id,
            epoch,
            plaintext,
        } => Event::MessageReceived {
            group_id: group_id.to_string(),
            epoch,
            text: String::from_utf8_lossy(&plaintext).into_owned(),
        },
        AppEvent::EpochAdvanced { group_id, epoch } => Event::EpochAdvanced {
            group_id: group_id.to_string(),
            epoch,
        },
        AppEvent::GatewayConnected => Event::GatewayConnected,
        AppEvent::GatewayDisconnected => Event::GatewayDisconnected,
        AppEvent::Warning(text) => Event::Warning { text },
    }
}

fn parse_group(raw: &str) -> Result<GroupId, CitadelError> {
    raw.parse()
        .map(GroupId::from_uuid)
        .map_err(|e| CitadelError::Failed(format!("group id {raw:?}: {e}")))
}

fn parse_hex32(raw: &str) -> Result<[u8; 32], CitadelError> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return Err(CitadelError::Failed(
            "kt anchor must be 64 hex chars".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16)
            .map_err(|e| CitadelError::Failed(format!("kt anchor hex: {e}")))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
