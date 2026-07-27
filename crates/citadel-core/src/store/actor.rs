//! The store actor: one connection, one thread, one transaction per operation
//! (ADR-0007 §§3 and 5).
//!
//! One actor owns one SQLite connection on a dedicated blocking thread. That
//! serializes every access without blocking a UI thread and without requiring a
//! Tokio runtime anywhere in the client core — which is the concrete reason
//! ADR-0007 replaced PLAN §4's `sqlx` choice for this store: OpenMLS's storage
//! trait is synchronous, and driving an async provider under it would have meant
//! `block_in_place` and a multithreaded runtime in every client call.
//!
//! Every state-changing operation runs inside **one** `rusqlite::Transaction`
//! with `TransactionBehavior::Immediate`. The transaction constructs a borrowing
//! [`StoreProvider`], loads the group from durable state, performs the MLS
//! operation, writes the matching application row, allocates the operation
//! sequence, writes the ledger row and outcome, and commits before returning
//! success. There is no network wait while a transaction is open.
//!
//! Because the ledger row and the mutation share the transaction, an absent
//! ledger row after a crash is **proof** the mutation did not apply. That is the
//! whole reconciliation argument, and it is why nothing here writes a receipt
//! "alongside" the work.

use super::error::StoreError;
use super::ledger::{
    check_operation, fingerprint, high_water, record_outcome, LedgerCheck, OperationId,
    OperationKind, RetainedOutcome,
};
use super::lifecycle::{destroy_profile, open_or_create, DestructionReport, OpenedStore};
use super::lock::ProfileLock;
use super::paths::ProfilePaths;
use super::provider::StoreProvider;
use crate::credential::IdentityVerifier;
use crate::group::{DmGroup, PreparedCommit, ReceiveOutcome};
use crate::identity::DeviceIdentity;
use crate::store::credentials::CredentialStore;
use crate::store::key::DatabaseEncryptionKey;
use citadel_proto::ids::GroupId as ProtoGroupId;
use openmls::prelude::KeyPackage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HashType;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The typed result of one state-changing operation.
///
/// Every variant is what the operation returned AND what a retry of the same
/// operation ID gets back, byte for byte, without the mutation happening again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationOutcome {
    /// A group was created at this epoch.
    GroupCreated {
        /// Epoch after creation.
        epoch: u64,
    },
    /// A Welcome was accepted at this epoch.
    Joined {
        /// Epoch after joining.
        epoch: u64,
    },
    /// Members were added; these are the exact bytes to submit.
    MembersAdded {
        /// Serialized commit `MlsMessageOut`.
        commit_bytes: Vec<u8>,
        /// Serialized Welcome `MlsMessageOut`.
        welcome_bytes: Vec<u8>,
    },
    /// An application message was encrypted; these are the exact wire bytes.
    Sent {
        /// Serialized application `MlsMessageOut`.
        ciphertext: Vec<u8>,
    },
    /// An application message was decrypted.
    ReceivedApplication {
        /// Unpadded plaintext.
        plaintext: Vec<u8>,
        /// True if this delivery was a duplicate and no MLS state advanced.
        deduplicated: bool,
    },
    /// A peer commit was merged.
    CommitMerged {
        /// Epoch after the merge.
        epoch: u64,
    },
    /// A self-update was prepared but not merged.
    SelfUpdatePrepared {
        /// Exact commit bytes to submit.
        commit_bytes: Vec<u8>,
        /// Epoch reached only after confirmation.
        proposed_epoch: u64,
    },
    /// A prepared self-update was merged.
    SelfUpdateConfirmed {
        /// Epoch after the merge.
        epoch: u64,
    },
    /// A prepared self-update was discarded.
    SelfUpdateAborted {
        /// Epoch, unchanged.
        epoch: u64,
    },
    /// A signed KT tree head advanced the anti-rollback checkpoint.
    KtHeadAccepted {
        /// Accepted tree size.
        tree_size: u64,
    },
}

impl OperationOutcome {
    /// The stable discriminator stored in the ledger's `outcome_kind`.
    fn kind(&self) -> &'static str {
        match self {
            OperationOutcome::GroupCreated { .. } => "group_created",
            OperationOutcome::Joined { .. } => "joined",
            OperationOutcome::MembersAdded { .. } => "members_added",
            OperationOutcome::Sent { .. } => "sent",
            OperationOutcome::ReceivedApplication { .. } => "received_application",
            OperationOutcome::CommitMerged { .. } => "commit_merged",
            OperationOutcome::SelfUpdatePrepared { .. } => "self_update_prepared",
            OperationOutcome::SelfUpdateConfirmed { .. } => "self_update_confirmed",
            OperationOutcome::SelfUpdateAborted { .. } => "self_update_aborted",
            OperationOutcome::KtHeadAccepted { .. } => "kt_head_accepted",
        }
    }

    fn to_retained(&self) -> Result<RetainedOutcome, StoreError> {
        Ok(RetainedOutcome {
            kind: self.kind().to_string(),
            bytes: serde_json::to_vec(self)
                .map_err(|error| StoreError::Codec(super::codec::CodecError::Json(error)))?,
        })
    }

    fn from_retained(retained: &RetainedOutcome) -> Result<Self, StoreError> {
        let outcome: OperationOutcome = serde_json::from_slice(&retained.bytes)
            .map_err(|error| StoreError::Codec(super::codec::CodecError::Json(error)))?;
        if outcome.kind() != retained.kind {
            // The stored discriminator and the stored payload disagree, which no
            // write path produces. Reconciliation, not a guess.
            return Err(StoreError::StoreOutcomeIndeterminate);
        }
        Ok(outcome)
    }
}

/// A conversation row, as listed to a UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRow {
    /// The group this conversation belongs to.
    pub group_id: ProtoGroupId,
    /// Optional local title. Plaintext, and inside SQLCipher (ADR-0007 §4).
    pub title: Option<String>,
    /// Cached durable epoch.
    pub last_epoch: u64,
}

/// A stored local message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    /// Monotonic local row id.
    pub id: i64,
    /// Group.
    pub group_id: ProtoGroupId,
    /// `"outgoing"` or `"incoming"`.
    pub direction: String,
    /// Epoch the message belonged to.
    pub epoch: u64,
    /// Decrypted plaintext. ADR-0007 §6: NOT covered by the forward-secrecy
    /// claim — a compromise holding the database encryption key reads it.
    pub plaintext: Vec<u8>,
}

/// A transmission whose transport outcome is not yet final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransmission {
    /// The idempotency key to retry under.
    pub idempotency_key: [u8; 16],
    /// Group.
    pub group_id: ProtoGroupId,
    /// `"application"`, `"commit"`, or `"welcome"`.
    pub kind: String,
    /// The EXACT bytes to retry. Not regenerated: regenerating would advance
    /// MLS state a second time.
    pub wire_bytes: Vec<u8>,
    /// For a commit, the epoch reached only after confirmation.
    pub proposed_epoch: Option<u64>,
}

/// The persisted anti-rollback checkpoint (ADR-0001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtCheckpoint {
    /// Highest accepted tree size.
    pub tree_size: u64,
    /// Its root hash.
    pub root_hash: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Request shapes. These are the "typed request fields" ADR-0007 §5 fingerprints.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CreateGroupRequest<'a> {
    group_id: [u8; 16],
    title: Option<&'a str>,
}

#[derive(Serialize)]
struct JoinRequest<'a> {
    group_id: [u8; 16],
    welcome_bytes: &'a [u8],
}

#[derive(Serialize)]
struct AddMembersRequest {
    group_id: [u8; 16],
    key_package_digests: Vec<Vec<u8>>,
}

#[derive(Serialize)]
struct SendRequest<'a> {
    group_id: [u8; 16],
    plaintext: &'a [u8],
}

#[derive(Serialize)]
struct ReceiveRequest<'a> {
    group_id: [u8; 16],
    message_bytes: &'a [u8],
}

#[derive(Serialize)]
struct GroupOnlyRequest {
    group_id: [u8; 16],
}

#[derive(Serialize)]
struct KtHeadRequest<'a> {
    tree_size: u64,
    root_hash: &'a [u8],
}

// ---------------------------------------------------------------------------
// The actor
// ---------------------------------------------------------------------------

/// The state the actor thread owns.
pub(crate) struct Actor {
    connection: Connection,
    key: DatabaseEncryptionKey,
    paths: ProfilePaths,
    credentials: Arc<dyn CredentialStore>,
    /// Held for the whole actor lifetime and released last, by dropping the
    /// actor after destruction.
    lock: ProfileLock,
}

type Job = Box<dyn FnOnce(&mut Actor) + Send>;

/// A handle to one open local encrypted client store.
///
/// Every method blocks until the actor has committed or rolled back, because
/// the caller's next decision depends on a durable outcome and returning early
/// would be a lie about persistence.
pub struct LocalStore {
    jobs: std::sync::mpsc::Sender<Job>,
    thread: Option<std::thread::JoinHandle<()>>,
    paths: ProfilePaths,
    backend_name: &'static str,
}

impl LocalStore {
    /// Open, or first-create, the profile store.
    ///
    /// Acquires the exclusive profile lock first, then runs ADR-0007 §2's
    /// startup state machine, then hardens and verifies the connection.
    pub fn open(
        paths: ProfilePaths,
        credentials: Arc<dyn CredentialStore>,
    ) -> Result<Self, StoreError> {
        paths.prepare()?;
        let backend_name = credentials.backend_name();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), StoreError>>();
        let (jobs_tx, jobs_rx) = std::sync::mpsc::channel::<Job>();
        let thread_paths = paths.clone();

        let thread = std::thread::Builder::new()
            .name("citadel-store".into())
            .spawn(move || {
                // The lock is taken on the actor thread so its handle lives and
                // dies with the actor, exactly as ADR-0007 §2 requires.
                let lock = match ProfileLock::acquire(&thread_paths) {
                    Ok(lock) => lock,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let opened = match open_or_create(&thread_paths, credentials.as_ref()) {
                    Ok(opened) => opened,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let OpenedStore { connection, key } = opened;
                let mut actor = Actor {
                    connection,
                    key,
                    paths: thread_paths,
                    credentials,
                    lock,
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                // Ends when every sender is dropped, i.e. on `close`/drop.
                while let Ok(job) = jobs_rx.recv() {
                    job(&mut actor);
                }
            })
            .map_err(|error| StoreError::io(paths.root(), error))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                jobs: jobs_tx,
                thread: Some(thread),
                paths,
                backend_name,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(StoreError::ActorStopped)
            }
        }
    }

    /// This profile's fixed paths, for snapshot copying and residual reporting.
    pub fn paths(&self) -> &ProfilePaths {
        &self.paths
    }

    /// The concrete credential backend in use, proved by running rather than by
    /// reading build configuration.
    pub fn credential_backend(&self) -> &'static str {
        self.backend_name
    }

    fn call<R: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Actor) -> R + Send + 'static,
    ) -> Result<R, StoreError> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.jobs
            .send(Box::new(move |actor| {
                let _ = tx.send(job(actor));
            }))
            .map_err(|_| StoreError::ActorStopped)?;
        rx.recv().map_err(|_| StoreError::ActorStopped)
    }

    /// Close the store: stop the actor, close the connection, release the lock.
    ///
    /// SQLCipher holds key material for the connection lifetime, so closing is
    /// required before profile destruction and before a snapshot is taken.
    pub fn close(mut self) -> Result<(), StoreError> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), StoreError> {
        // Dropping the only sender ends the actor's receive loop, which drops
        // the connection and then the lock.
        let (dead, _) = std::sync::mpsc::channel();
        let sender = std::mem::replace(&mut self.jobs, dead);
        drop(sender);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| StoreError::ActorStopped)?;
        }
        Ok(())
    }

    /// Destroy this local profile: delete all three credential entries, remove
    /// every file, and report structured partial failure.
    pub fn destroy(mut self) -> Result<DestructionReport, StoreError> {
        let report = self.call(|actor| {
            // ADR-0007 §6: destruction CLOSES the actor's connection first.
            // Two reasons, and the second is not theoretical: SQLCipher holds
            // key material for the connection lifetime, and Windows refuses to
            // delete a file that is still open, so leaving the connection alive
            // would silently turn every destroy into a partial failure that
            // reports the database as a residual path.
            //
            // The placeholder is unreachable: `destroy` consumes `self`, so no
            // further call can be submitted, and `shutdown` runs immediately
            // after this job returns.
            let placeholder = Connection::open_in_memory()?;
            drop(std::mem::replace(&mut actor.connection, placeholder));

            Ok::<_, StoreError>(destroy_profile(
                &actor.paths,
                actor.credentials.as_ref(),
                actor.lock.path(),
            ))
        })??;
        // The lock releases here, after deletion, so it is genuinely released
        // last.
        self.shutdown()?;
        Ok(report)
    }

    // ---- state-changing operations -------------------------------------

    /// Create a group with this device as its sole member.
    pub fn create_group(
        &self,
        operation_id: OperationId,
        identity: Arc<DeviceIdentity>,
        group_id: ProtoGroupId,
        title: Option<String>,
    ) -> Result<OperationOutcome, StoreError> {
        self.call(move |actor| {
            let request = CreateGroupRequest {
                group_id: *group_id.as_uuid().as_bytes(),
                title: title.as_deref(),
            };
            let print = fingerprint(OperationKind::CreateGroup, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::CreateGroup,
                print,
                move |transaction| {
                    let provider = StoreProvider::new(transaction);
                    let group = DmGroup::create(&provider, &identity, group_id)?;
                    let epoch = group.epoch();
                    transaction.execute(
                        "INSERT INTO citadel_conversations (group_id, created_at, title, last_epoch)
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            group_id.as_uuid().as_bytes().as_slice(),
                            super::schema::now_unix_seconds(),
                            title,
                            epoch as i64
                        ],
                    )?;
                    Ok(OperationOutcome::GroupCreated { epoch })
                },
            )
        })?
    }

    /// Accept a Welcome and persist the resulting group.
    pub fn join_from_welcome<V>(
        &self,
        operation_id: OperationId,
        group_id: ProtoGroupId,
        welcome_bytes: Vec<u8>,
        verifier: Arc<V>,
        title: Option<String>,
    ) -> Result<OperationOutcome, StoreError>
    where
        V: IdentityVerifier + Send + Sync + 'static,
    {
        self.call(move |actor| {
            let request = JoinRequest {
                group_id: *group_id.as_uuid().as_bytes(),
                welcome_bytes: &welcome_bytes,
            };
            let print = fingerprint(OperationKind::JoinFromWelcome, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::JoinFromWelcome,
                print,
                move |transaction| {
                    let provider = StoreProvider::new(transaction);
                    // INV-4 runs inside the transaction: a rejected member means
                    // no group state is committed at all.
                    let group = DmGroup::join_from_welcome(&provider, &welcome_bytes, &verifier)?;
                    let epoch = group.epoch();
                    transaction.execute(
                        "INSERT INTO citadel_conversations (group_id, created_at, title, last_epoch)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(group_id) DO UPDATE SET last_epoch = excluded.last_epoch",
                        rusqlite::params![
                            group_id.as_uuid().as_bytes().as_slice(),
                            super::schema::now_unix_seconds(),
                            title,
                            epoch as i64
                        ],
                    )?;
                    Ok(OperationOutcome::Joined { epoch })
                },
            )
        })?
    }

    /// Add members and persist the exact commit and Welcome to retry.
    pub fn add_members<V>(
        &self,
        operation_id: OperationId,
        identity: Arc<DeviceIdentity>,
        group_id: ProtoGroupId,
        key_packages: Vec<KeyPackage>,
        verifier: Arc<V>,
    ) -> Result<OperationOutcome, StoreError>
    where
        V: IdentityVerifier + Send + Sync + 'static,
    {
        self.call(move |actor| {
            let digests = key_packages
                .iter()
                .map(|package| {
                    let bytes = serde_json::to_vec(package).map_err(|error| {
                        StoreError::Codec(super::codec::CodecError::Json(error))
                    })?;
                    sha256(&bytes)
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            let request = AddMembersRequest {
                group_id: *group_id.as_uuid().as_bytes(),
                key_package_digests: digests,
            };
            let print = fingerprint(OperationKind::AddMembers, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::AddMembers,
                print,
                move |transaction| {
                    let provider = StoreProvider::new(transaction);
                    let mut group = load_group(transaction, &provider, group_id)?;
                    let output =
                        group.add_members(&provider, &identity, &key_packages, &verifier)?;
                    let epoch = group.epoch();
                    update_epoch(transaction, group_id, epoch)?;
                    // The commit is merged locally, so the exact bytes must be
                    // durable BEFORE the caller is told it succeeded; otherwise a
                    // crash leaves an advanced group nobody can retransmit for.
                    insert_pending(
                        transaction,
                        operation_id,
                        group_id,
                        "commit",
                        &output.commit_bytes,
                        Some(epoch),
                    )?;
                    insert_pending_with_key(
                        transaction,
                        welcome_key(operation_id),
                        operation_id,
                        group_id,
                        "welcome",
                        &output.welcome_bytes,
                        None,
                    )?;
                    Ok(OperationOutcome::MembersAdded {
                        commit_bytes: output.commit_bytes,
                        welcome_bytes: output.welcome_bytes,
                    })
                },
            )
        })?
    }

    /// Generate one KeyPackage for the one-time pool, persisting its private
    /// init and encryption keys into the store.
    ///
    /// Deliberately **not** a ledgered operation. Every other state-changing
    /// call is idempotent under its operation ID; this one must not be. A
    /// KeyPackage is one-time-use, so a retry has to produce a *new* package —
    /// returning the previous one would hand two joiners the same init key.
    /// It still runs in one immediate transaction, so a failure leaves no
    /// half-written private key behind.
    pub fn new_key_package(&self, identity: Arc<DeviceIdentity>) -> Result<KeyPackage, StoreError> {
        self.call(move |actor| {
            let transaction = actor
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let package = {
                let provider = StoreProvider::new(&transaction);
                identity.new_key_package(&provider)?
            };
            transaction.commit()?;
            Ok(package)
        })?
    }

    /// Encrypt and persist an outgoing application message.
    pub fn send(
        &self,
        operation_id: OperationId,
        identity: Arc<DeviceIdentity>,
        group_id: ProtoGroupId,
        plaintext: Vec<u8>,
    ) -> Result<OperationOutcome, StoreError> {
        self.call(move |actor| {
            let request = SendRequest {
                group_id: *group_id.as_uuid().as_bytes(),
                plaintext: &plaintext,
            };
            let print = fingerprint(OperationKind::Send, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::Send,
                print,
                move |transaction| {
                    let provider = StoreProvider::new(transaction);
                    let mut group = load_group(transaction, &provider, group_id)?;
                    let ciphertext = group.send(&provider, &identity, &plaintext)?;
                    let epoch = group.epoch();
                    // One atomic unit: advanced sender ratchet + plaintext row +
                    // exact ciphertext + idempotency key.
                    transaction.execute(
                        "INSERT INTO citadel_messages
                         (group_id, direction, epoch, sender, plaintext, received_at, dedup_key)
                     VALUES (?1, 'outgoing', ?2, NULL, ?3, ?4, NULL)",
                        rusqlite::params![
                            group_id.as_uuid().as_bytes().as_slice(),
                            epoch as i64,
                            plaintext,
                            super::schema::now_unix_seconds()
                        ],
                    )?;
                    insert_pending(
                        transaction,
                        operation_id,
                        group_id,
                        "application",
                        &ciphertext,
                        None,
                    )?;
                    Ok(OperationOutcome::Sent { ciphertext })
                },
            )
        })?
    }

    /// Process one incoming MLS message and persist its effect.
    pub fn receive<V>(
        &self,
        operation_id: OperationId,
        group_id: ProtoGroupId,
        message_bytes: Vec<u8>,
        verifier: Arc<V>,
    ) -> Result<OperationOutcome, StoreError>
    where
        V: IdentityVerifier + Send + Sync + 'static,
    {
        self.call(move |actor| {
            let request = ReceiveRequest {
                group_id: *group_id.as_uuid().as_bytes(),
                message_bytes: &message_bytes,
            };
            // The kind is fingerprinted as ReceiveApplication for both cases: the
            // caller cannot know which it is before decrypting, so using two
            // kinds would make a retry look like an OperationIdConflict.
            let print = fingerprint(OperationKind::ReceiveApplication, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::ReceiveApplication,
                print,
                move |transaction| {
                    let dedup = sha256(&message_bytes)?;
                    // Delivery deduplication is checked BEFORE any MLS work, so a
                    // replayed delivery cannot advance a ratchet or produce a
                    // second plaintext row.
                    if let Some(plaintext) = transaction
                        .query_row(
                            "SELECT plaintext FROM citadel_messages WHERE dedup_key = ?1",
                            [&dedup],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()?
                    {
                        return Ok(OperationOutcome::ReceivedApplication {
                            plaintext,
                            deduplicated: true,
                        });
                    }

                    let provider = StoreProvider::new(transaction);
                    let mut group = load_group(transaction, &provider, group_id)?;
                    match group.receive(&provider, &message_bytes, &verifier)? {
                        ReceiveOutcome::Application(plaintext) => {
                            let epoch = group.epoch();
                            transaction.execute(
                                "INSERT INTO citadel_messages
                                     (group_id, direction, epoch, sender, plaintext, received_at, dedup_key)
                                 VALUES (?1, 'incoming', ?2, NULL, ?3, ?4, ?5)",
                                rusqlite::params![
                                    group_id.as_uuid().as_bytes().as_slice(),
                                    epoch as i64,
                                    plaintext,
                                    super::schema::now_unix_seconds(),
                                    dedup
                                ],
                            )?;
                            Ok(OperationOutcome::ReceivedApplication {
                                plaintext,
                                deduplicated: false,
                            })
                        }
                        ReceiveOutcome::CommitMerged { epoch } => {
                            update_epoch(transaction, group_id, epoch)?;
                            transaction.execute(
                                "INSERT INTO citadel_delivery_cursors (group_id, last_sequence)
                                 VALUES (?1, ?2)
                                 ON CONFLICT(group_id) DO UPDATE
                                   SET last_sequence = MAX(last_sequence, excluded.last_sequence)",
                                rusqlite::params![
                                    group_id.as_uuid().as_bytes().as_slice(),
                                    epoch as i64
                                ],
                            )?;
                            Ok(OperationOutcome::CommitMerged { epoch })
                        }
                    }
                },
            )
        })?
    }

    /// Prepare a self-update commit and persist its exact bytes.
    pub fn prepare_self_update(
        &self,
        operation_id: OperationId,
        identity: Arc<DeviceIdentity>,
        group_id: ProtoGroupId,
    ) -> Result<OperationOutcome, StoreError> {
        self.call(move |actor| {
            let request = GroupOnlyRequest {
                group_id: *group_id.as_uuid().as_bytes(),
            };
            let print = fingerprint(OperationKind::PrepareSelfUpdate, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::PrepareSelfUpdate,
                print,
                move |transaction| {
                    let provider = StoreProvider::new(transaction);
                    let mut group = load_group(transaction, &provider, group_id)?;
                    let prepared = group.prepare_self_update(&provider, &identity)?;
                    insert_pending(
                        transaction,
                        operation_id,
                        group_id,
                        "commit",
                        prepared.commit_bytes(),
                        Some(prepared.proposed_epoch()),
                    )?;
                    Ok(OperationOutcome::SelfUpdatePrepared {
                        commit_bytes: prepared.commit_bytes().to_vec(),
                        proposed_epoch: prepared.proposed_epoch(),
                    })
                },
            )
        })?
    }

    /// Merge a prepared self-update after transport accepted it.
    pub fn confirm_self_update(
        &self,
        operation_id: OperationId,
        group_id: ProtoGroupId,
    ) -> Result<OperationOutcome, StoreError> {
        self.finish_self_update(operation_id, group_id, true)
    }

    /// Discard a prepared self-update after transport rejected it.
    pub fn abort_self_update(
        &self,
        operation_id: OperationId,
        group_id: ProtoGroupId,
    ) -> Result<OperationOutcome, StoreError> {
        self.finish_self_update(operation_id, group_id, false)
    }

    fn finish_self_update(
        &self,
        operation_id: OperationId,
        group_id: ProtoGroupId,
        confirm: bool,
    ) -> Result<OperationOutcome, StoreError> {
        self.call(move |actor| {
            let kind = if confirm {
                OperationKind::ConfirmSelfUpdate
            } else {
                OperationKind::AbortSelfUpdate
            };
            let request = GroupOnlyRequest {
                group_id: *group_id.as_uuid().as_bytes(),
            };
            let print = fingerprint(kind, &request)?;
            actor.mutate(operation_id, kind, print, move |transaction| {
                let pending = pending_commit(transaction, group_id)?
                    .ok_or(crate::group::GroupError::NoPendingCommit)?;
                let provider = StoreProvider::new(transaction);
                let mut group =
                    DmGroup::load(&provider, &group_id, Some(pending.wire_bytes.clone()))?
                        .ok_or(StoreError::UnknownGroup)?;
                let prepared = PreparedCommit::from_persisted(
                    pending.wire_bytes.clone(),
                    pending.proposed_epoch.unwrap_or_default(),
                );
                if confirm {
                    group.confirm_self_update(&provider, &prepared)?;
                } else {
                    group.abort_self_update(&provider, &prepared)?;
                }
                let epoch = group.epoch();
                update_epoch(transaction, group_id, epoch)?;
                transaction.execute(
                    "DELETE FROM citadel_pending_transmissions WHERE idempotency_key = ?1",
                    [pending.idempotency_key.as_slice()],
                )?;
                Ok(if confirm {
                    OperationOutcome::SelfUpdateConfirmed { epoch }
                } else {
                    OperationOutcome::SelfUpdateAborted { epoch }
                })
            })
        })?
    }

    /// Accept a signed KT tree head, advancing the anti-rollback checkpoint.
    ///
    /// A shorter or forked head is refused without advancing the stored
    /// checkpoint (ADR-0001's anti-rollback rule).
    pub fn accept_kt_head(
        &self,
        operation_id: OperationId,
        tree_size: u64,
        root_hash: Vec<u8>,
    ) -> Result<OperationOutcome, StoreError> {
        self.call(move |actor| {
            let request = KtHeadRequest {
                tree_size,
                root_hash: &root_hash,
            };
            let print = fingerprint(OperationKind::AcceptKtHead, &request)?;
            actor.mutate(
                operation_id,
                OperationKind::AcceptKtHead,
                print,
                move |transaction| {
                    let current: Option<(i64, Vec<u8>)> = transaction
                        .query_row(
                            "SELECT tree_size, root_hash FROM citadel_kt_checkpoint WHERE id = 1",
                            [],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if let Some((current_size, current_hash)) = current {
                        if (tree_size as i64) < current_size {
                            return Err(StoreError::StoreStateInconsistent(
                                "a KT tree head shorter than the persisted checkpoint was offered",
                            ));
                        }
                        if tree_size as i64 == current_size && current_hash != root_hash {
                            return Err(StoreError::StoreStateInconsistent(
                                "a forked KT tree head at the persisted size was offered",
                            ));
                        }
                    }
                    transaction.execute(
                        "INSERT INTO citadel_kt_checkpoint (id, tree_size, root_hash, accepted_at)
                         VALUES (1, ?1, ?2, ?3)
                         ON CONFLICT(id) DO UPDATE SET
                           tree_size = excluded.tree_size,
                           root_hash = excluded.root_hash,
                           accepted_at = excluded.accepted_at",
                        rusqlite::params![
                            tree_size as i64,
                            root_hash,
                            super::schema::now_unix_seconds()
                        ],
                    )?;
                    Ok(OperationOutcome::KtHeadAccepted { tree_size })
                },
            )
        })?
    }

    // ---- reads -----------------------------------------------------------

    /// Every conversation this profile holds.
    pub fn conversations(&self) -> Result<Vec<ConversationRow>, StoreError> {
        self.call(|actor| {
            let mut statement = actor.connection.prepare(
                "SELECT group_id, title, last_epoch FROM citadel_conversations ORDER BY created_at",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(id, title, epoch)| {
                    Ok(ConversationRow {
                        group_id: group_id_from_bytes(&id)?,
                        title,
                        last_epoch: epoch as u64,
                    })
                })
                .collect()
        })?
    }

    /// Stored messages for one group, oldest first.
    pub fn messages(&self, group_id: ProtoGroupId) -> Result<Vec<MessageRow>, StoreError> {
        self.call(move |actor| {
            let mut statement = actor.connection.prepare(
                "SELECT id, direction, epoch, plaintext FROM citadel_messages
                  WHERE group_id = ?1 ORDER BY id",
            )?;
            let rows = statement
                .query_map([group_id.as_uuid().as_bytes().as_slice()], |row| {
                    Ok(MessageRow {
                        id: row.get(0)?,
                        group_id,
                        direction: row.get(1)?,
                        epoch: row.get::<_, i64>(2)? as u64,
                        plaintext: row.get(3)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?
    }

    /// Transmissions whose transport outcome is not final, with the EXACT bytes
    /// to retry. Read after the transaction, per ADR-0007 §5.
    pub fn pending_transmissions(&self) -> Result<Vec<PendingTransmission>, StoreError> {
        self.call(|actor| {
            let mut statement = actor.connection.prepare(
                "SELECT idempotency_key, group_id, kind, wire_bytes, proposed_epoch
                   FROM citadel_pending_transmissions ORDER BY created_at, rowid",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(key, group, kind, wire, epoch)| {
                    let mut idempotency_key = [0u8; 16];
                    if key.len() != 16 {
                        return Err(StoreError::StoreStateInconsistent(
                            "a pending transmission has a malformed idempotency key",
                        ));
                    }
                    idempotency_key.copy_from_slice(&key);
                    Ok(PendingTransmission {
                        idempotency_key,
                        group_id: group_id_from_bytes(&group)?,
                        kind,
                        wire_bytes: wire,
                        proposed_epoch: epoch.map(|e| e as u64),
                    })
                })
                .collect()
        })?
    }

    /// Mark a pending transmission delivered, in its own transaction.
    pub fn acknowledge_transmission(&self, idempotency_key: [u8; 16]) -> Result<(), StoreError> {
        self.call(move |actor| {
            actor.connection.execute(
                "DELETE FROM citadel_pending_transmissions WHERE idempotency_key = ?1",
                [idempotency_key.as_slice()],
            )?;
            Ok(())
        })?
    }

    /// The persisted anti-rollback checkpoint, if one has been accepted.
    pub fn kt_checkpoint(&self) -> Result<Option<KtCheckpoint>, StoreError> {
        self.call(|actor| {
            let row = actor
                .connection
                .query_row(
                    "SELECT tree_size, root_hash FROM citadel_kt_checkpoint WHERE id = 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            Ok(row.map(|(tree_size, root_hash)| KtCheckpoint {
                tree_size: tree_size as u64,
                root_hash,
            }))
        })?
    }

    /// The current high-water operation sequence. Never decreases.
    pub fn operation_high_water(&self) -> Result<i64, StoreError> {
        self.call(|actor| {
            let transaction = actor.connection.transaction()?;
            let value = high_water(&transaction)?;
            transaction.rollback()?;
            Ok(value)
        })?
    }

    /// The durable epoch of one group, loaded from persisted state rather than
    /// from any in-memory group object.
    pub fn group_epoch(&self, group_id: ProtoGroupId) -> Result<u64, StoreError> {
        self.call(move |actor| {
            let transaction = actor.connection.transaction()?;
            let provider = StoreProvider::new(&transaction);
            let group =
                DmGroup::load(&provider, &group_id, None)?.ok_or(StoreError::UnknownGroup)?;
            let epoch = group.epoch();
            transaction.rollback()?;
            Ok(epoch)
        })?
    }

    /// Run `cipher_integrity_check` as explicit maintenance.
    pub fn verify_integrity(&self) -> Result<(), StoreError> {
        self.call(|actor| super::open::cipher_integrity_check(&actor.connection))?
    }

    /// The database encryption key currently in use.
    ///
    /// Test configuration only, and it exists for exactly one reason: ADR-0007
    /// §6's forward-secrecy evidence hands the attacker the correct key, so the
    /// test must be able to obtain it. No production build compiles this.
    #[cfg(any(test, feature = "testing"))]
    pub fn database_encryption_key_for_evidence(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, StoreError> {
        self.call(|actor| zeroize::Zeroizing::new(*actor.key.as_bytes()))
    }
}

impl std::fmt::Debug for LocalStore {
    /// Never renders any store contents: a `{:?}` in a log or a test failure
    /// must not become a way for plaintext or key material to escape.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStore")
            .field("root", &self.paths.root())
            .field("credential_backend", &self.backend_name)
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl Drop for LocalStore {
    fn drop(&mut self) {
        // Best effort: an explicit `close` is preferred because it surfaces
        // errors, but a dropped handle must still release the lock rather than
        // leaving the profile unopenable until the process exits.
        let _ = self.shutdown();
    }
}

impl Actor {
    /// Run one state-changing operation as a single atomic unit.
    ///
    /// Order matters and is ADR-0007 §5's: check the ledger, do the work, write
    /// the ledger row and outcome, commit. A commit failure is treated as
    /// **indeterminate** and reconciled from durable state rather than retried.
    fn mutate<F>(
        &mut self,
        operation_id: OperationId,
        kind: OperationKind,
        request_fingerprint: Vec<u8>,
        work: F,
    ) -> Result<OperationOutcome, StoreError>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<OperationOutcome, StoreError>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        match check_operation(&transaction, operation_id, kind, &request_fingerprint)? {
            LedgerCheck::Replay(retained) => {
                // No mutation at all: the stored result is returned as it was.
                transaction.rollback()?;
                return OperationOutcome::from_retained(&retained);
            }
            LedgerCheck::Fresh => {}
        }

        let outcome = match work(&transaction) {
            Ok(outcome) => outcome,
            Err(error) => {
                // Any SQL, serialization, or OpenMLS failure before the commit
                // point rolls back and discards the loaded group object.
                let _ = transaction.rollback();
                return Err(error);
            }
        };

        let retained = outcome.to_retained()?;
        if let Err(error) = record_outcome(
            &transaction,
            operation_id,
            kind,
            &request_fingerprint,
            &retained,
        ) {
            let _ = transaction.rollback();
            return Err(error);
        }

        match transaction.commit() {
            Ok(()) => Ok(outcome),
            Err(_) => {
                // Indeterminate. Discard everything in memory, reopen, let
                // SQLite recover, and decide from the durable receipt. Never
                // blindly repeat an MLS mutation.
                self.reopen()?;
                self.reconcile(operation_id, kind, &request_fingerprint)
            }
        }
    }

    /// Close and reopen the connection so SQLite performs recovery.
    fn reopen(&mut self) -> Result<(), StoreError> {
        let opened = super::open::open_hardened(
            &self.paths.database(),
            &self.key,
            super::open::OpenIntent::Existing,
        )?;
        self.connection = opened;
        super::open::cipher_integrity_check(&self.connection)?;
        Ok(())
    }

    /// After an indeterminate commit, decide from the durable ledger.
    fn reconcile(
        &mut self,
        operation_id: OperationId,
        kind: OperationKind,
        request_fingerprint: &[u8],
    ) -> Result<OperationOutcome, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let checked = check_operation(&transaction, operation_id, kind, request_fingerprint);
        let _ = transaction.rollback();
        match checked {
            // The receipt is there, so the whole atomic unit applied.
            Ok(LedgerCheck::Replay(retained)) => OperationOutcome::from_retained(&retained),
            // No receipt proves the transaction did not apply, because the
            // receipt and the mutation share one atomic unit.
            Ok(LedgerCheck::Fresh) => Err(StoreError::StoreOutcomeIndeterminate),
            Err(StoreError::OperationReceiptExpired) => Err(StoreError::OperationReceiptExpired),
            Err(_) => Err(StoreError::StoreOutcomeIndeterminate),
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    RustCrypto::default()
        .hash(HashType::Sha2_256, bytes)
        .map_err(|error| StoreError::Migration(format!("sha-256 unavailable: {error:?}")))
}

fn group_id_from_bytes(bytes: &[u8]) -> Result<ProtoGroupId, StoreError> {
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| StoreError::StoreStateInconsistent("a stored group id is not 16 bytes"))?;
    Ok(ProtoGroupId::from_uuid(uuid::Uuid::from_bytes(array)))
}

/// Load a group from durable state, reattaching any persisted pending commit.
fn load_group<'a>(
    transaction: &rusqlite::Transaction<'_>,
    provider: &StoreProvider<'a>,
    group_id: ProtoGroupId,
) -> Result<DmGroup, StoreError> {
    let pending = pending_commit(transaction, group_id)?.map(|row| row.wire_bytes);
    DmGroup::load(provider, &group_id, pending)?.ok_or(StoreError::UnknownGroup)
}

fn pending_commit(
    transaction: &rusqlite::Transaction<'_>,
    group_id: ProtoGroupId,
) -> Result<Option<PendingTransmission>, StoreError> {
    let row = transaction
        .query_row(
            "SELECT idempotency_key, wire_bytes, proposed_epoch
               FROM citadel_pending_transmissions
              WHERE group_id = ?1 AND kind = 'commit' AND proposed_epoch IS NOT NULL
              ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [group_id.as_uuid().as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((key, wire_bytes, epoch)) = row else {
        return Ok(None);
    };
    let mut idempotency_key = [0u8; 16];
    if key.len() != 16 {
        return Err(StoreError::StoreStateInconsistent(
            "a pending transmission has a malformed idempotency key",
        ));
    }
    idempotency_key.copy_from_slice(&key);
    Ok(Some(PendingTransmission {
        idempotency_key,
        group_id,
        kind: "commit".into(),
        wire_bytes,
        proposed_epoch: epoch.map(|e| e as u64),
    }))
}

fn update_epoch(
    transaction: &rusqlite::Transaction<'_>,
    group_id: ProtoGroupId,
    epoch: u64,
) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE citadel_conversations SET last_epoch = ?2 WHERE group_id = ?1",
        rusqlite::params![group_id.as_uuid().as_bytes().as_slice(), epoch as i64],
    )?;
    Ok(())
}

/// A second idempotency key derived from the operation id, for the Welcome that
/// accompanies an add-members commit. Deriving rather than generating keeps it
/// reproducible across a retry of the same operation id.
fn welcome_key(operation_id: OperationId) -> [u8; 16] {
    let mut key = *operation_id.as_bytes();
    key[0] ^= 0x80;
    key
}

fn insert_pending(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: OperationId,
    group_id: ProtoGroupId,
    kind: &str,
    wire_bytes: &[u8],
    proposed_epoch: Option<u64>,
) -> Result<(), StoreError> {
    insert_pending_with_key(
        transaction,
        *operation_id.as_bytes(),
        operation_id,
        group_id,
        kind,
        wire_bytes,
        proposed_epoch,
    )
}

fn insert_pending_with_key(
    transaction: &rusqlite::Transaction<'_>,
    idempotency_key: [u8; 16],
    operation_id: OperationId,
    group_id: ProtoGroupId,
    kind: &str,
    wire_bytes: &[u8],
    proposed_epoch: Option<u64>,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO citadel_pending_transmissions
             (idempotency_key, group_id, kind, wire_bytes, proposed_epoch, operation_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            idempotency_key.as_slice(),
            group_id.as_uuid().as_bytes().as_slice(),
            kind,
            wire_bytes,
            proposed_epoch.map(|e| e as i64),
            operation_id.as_bytes().as_slice(),
            super::schema::now_unix_seconds()
        ],
    )?;
    Ok(())
}
