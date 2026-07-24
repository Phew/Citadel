//! The DM group state machine over OpenMLS (F2 create/join, F4 send/receive).
//!
//! Membership is authored by clients and validated by clients (INV-3, INV-4):
//! on join, every member's credential is verified against the KT log before the
//! group is accepted. Application plaintext is padded before encrypt and
//! unpadded after decrypt (ADR-0005 §3); the delivery service only ever handles
//! the resulting ciphertext (INV-1).

use crate::credential::{verify_member_credential, CredentialError, IdentityVerifier};
use crate::crypto::{create_config, join_config, Provider};
use crate::identity::DeviceIdentity;
use crate::padding::{pad, unpad, PadError};
use citadel_proto::ids::GroupId as ProtoGroupId;
use openmls::prelude::*;

/// Errors from group operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("padding: {0}")]
    Pad(#[from] PadError),
    #[error("a member credential failed KT verification (INV-4): {0}")]
    MemberRejected(#[from] CredentialError),
    #[error("mls error: {0}")]
    Mls(String),
    #[error("message type is not supported")]
    UnsupportedMessage,
    #[error("proposal-bearing commits are not supported")]
    ProposalBearingCommitDeferred,
    #[error("there is no pending local commit")]
    NoPendingCommit,
    #[error("the prepared commit does not match this group's pending commit")]
    PreparedCommitMismatch,
    #[error("incoming commit conflicts with a pending self-update")]
    PendingCommitConflictDeferred,
}

/// A joined DM group. Wraps the OpenMLS group; all mutation goes through here so
/// padding and member verification cannot be bypassed.
pub struct DmGroup {
    mls: MlsGroup,
    pending_self_update: Option<Vec<u8>>,
}

impl DmGroup {
    /// Create a new DM group with `identity` as the sole initial member. The
    /// `group_id` is the server-facing [`ProtoGroupId`] so wire addressing and
    /// MLS agree on one identifier.
    pub fn create(
        provider: &Provider,
        identity: &DeviceIdentity,
        group_id: ProtoGroupId,
    ) -> Result<Self, GroupError> {
        let gid = GroupId::from_slice(group_id.as_uuid().as_bytes());
        let mls = MlsGroup::new_with_group_id(
            provider,
            &identity.signer,
            &create_config(),
            gid,
            identity.credential_with_key.clone(),
        )
        .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        Ok(Self {
            mls,
            pending_self_update: None,
        })
    }

    /// Add members from their fetched KeyPackages in one commit (F2 step 2).
    /// Returns the serialized commit and Welcome for submission via the delivery
    /// service. The commit is merged locally immediately (the initiator is
    /// authoritative for its own send).
    pub fn add_members(
        &mut self,
        provider: &Provider,
        identity: &DeviceIdentity,
        key_packages: &[KeyPackage],
        verifier: &impl IdentityVerifier,
    ) -> Result<AddMembersOutput, GroupError> {
        // INV-4: the initiator rejects every fetched KeyPackage before
        // OpenMLS creates a commit, a Welcome, or any pending group state.
        for key_package in key_packages {
            let leaf = key_package.leaf_node();
            verify_member_credential(
                leaf.credential().serialized_content(),
                leaf.signature_key().as_slice(),
                verifier,
            )?;
        }
        let (commit, welcome, _group_info) = self
            .mls
            .add_members(provider, &identity.signer, key_packages)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        self.mls
            .merge_pending_commit(provider)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let commit_bytes = commit
            .to_bytes()
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        Ok(AddMembersOutput {
            commit_bytes,
            welcome_bytes,
        })
    }

    /// Join a group from a Welcome (F2 step 3). **Every member credential is
    /// verified against the KT log (INV-4) before the group is accepted**; any
    /// failure aborts the join and no group state is created. `welcome_bytes` is
    /// the serialized `MlsMessageOut` of kind Welcome delivered by the DS.
    pub fn join_from_welcome(
        provider: &Provider,
        welcome_bytes: &[u8],
        verifier: &impl IdentityVerifier,
    ) -> Result<Self, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(GroupError::Mls("message was not a Welcome".into())),
        };

        // The ratchet tree rides in the Welcome extension (see create_config).
        let staged = StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;

        // INV-4: verify EVERY member's credential against the KT log before we
        // accept the group. A single rejection aborts without joining.
        for member in staged.members() {
            verify_member_credential(
                member.credential.serialized_content(),
                &member.signature_key,
                verifier,
            )?;
        }

        let mls = staged
            .into_group(provider)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        Ok(Self {
            mls,
            pending_self_update: None,
        })
    }

    /// Encrypt an application message (F4 send). The plaintext is padded to a
    /// bucket before encryption (ADR-0005 §3). Returns the serialized
    /// `MlsMessageOut` for submission as an `Application` envelope.
    pub fn send(
        &mut self,
        provider: &Provider,
        identity: &DeviceIdentity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        let padded = pad(plaintext)?;
        let out = self
            .mls
            .create_message(provider, &identity.signer, &padded)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        out.to_bytes()
            .map_err(|e| GroupError::Mls(format!("{e:?}")))
    }

    /// Prepare a self-update commit for transport without advancing the local
    /// epoch. The caller confirms it only after transport acceptance, or aborts
    /// it after rejection. Delivery ordering and rebase remain M3.
    pub fn prepare_self_update(
        &mut self,
        provider: &Provider,
        identity: &DeviceIdentity,
    ) -> Result<PreparedCommit, GroupError> {
        let bundle = self
            .mls
            .self_update(provider, &identity.signer, LeafNodeParameters::default())
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let proposed_epoch = self
            .mls
            .pending_commit()
            .ok_or_else(|| GroupError::Mls("OpenMLS created no pending self-update".into()))?
            .epoch()
            .as_u64();
        let commit_bytes = match bundle.into_commit().to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.mls
                    .clear_pending_commit(provider.storage())
                    .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
                return Err(GroupError::Mls(format!("{error:?}")));
            }
        };
        self.pending_self_update = Some(commit_bytes.clone());
        Ok(PreparedCommit {
            commit_bytes,
            proposed_epoch,
        })
    }

    /// Merge the pending local commit after transport accepts it.
    pub fn confirm_self_update(
        &mut self,
        provider: &Provider,
        prepared: &PreparedCommit,
    ) -> Result<(), GroupError> {
        self.validate_prepared_commit(prepared)?;
        self.mls
            .merge_pending_commit(provider)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        self.pending_self_update = None;
        Ok(())
    }

    /// Discard the pending local commit after transport rejects it.
    pub fn abort_self_update(
        &mut self,
        provider: &Provider,
        prepared: &PreparedCommit,
    ) -> Result<(), GroupError> {
        self.validate_prepared_commit(prepared)?;
        self.mls
            .clear_pending_commit(provider.storage())
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        self.pending_self_update = None;
        Ok(())
    }

    /// Process incoming M2 traffic. Application messages return unpadded
    /// plaintext. Proposal-free staged commits are KT-verified and merged so
    /// peer self-updates advance the epoch. Commit ordering, conflict handling,
    /// and proposal-bearing commits remain M3.
    pub fn receive(
        &mut self,
        provider: &Provider,
        message_bytes: &[u8],
        verifier: &impl IdentityVerifier,
    ) -> Result<ReceiveOutcome, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(message_bytes)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|_| GroupError::UnsupportedMessage)?;
        if protocol.content_type() == ContentType::Commit && self.pending_self_update.is_some() {
            return Err(GroupError::PendingCommitConflictDeferred);
        }
        let processed = self
            .mls
            .process_message(provider, protocol)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(ReceiveOutcome::Application(unpad(&app.into_bytes())?))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if staged.queued_proposals().next().is_some() {
                    return Err(GroupError::ProposalBearingCommitDeferred);
                }
                if let Some(leaf) = staged.update_path_leaf_node() {
                    verify_member_credential(
                        leaf.credential().serialized_content(),
                        leaf.signature_key().as_slice(),
                        verifier,
                    )?;
                }
                let epoch = staged.epoch().as_u64();
                self.mls
                    .merge_staged_commit(provider, *staged)
                    .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
                Ok(ReceiveOutcome::CommitMerged { epoch })
            }
            _ => Err(GroupError::UnsupportedMessage),
        }
    }

    /// This client's current epoch (the client-declared `epoch` hint on submit,
    /// ADR-0005 §1).
    pub fn epoch(&self) -> u64 {
        self.mls.epoch().as_u64()
    }

    /// Number of members currently in the group.
    pub fn member_count(&self) -> usize {
        self.mls.members().count()
    }

    fn validate_prepared_commit(&self, prepared: &PreparedCommit) -> Result<(), GroupError> {
        if self.mls.pending_commit().is_none() {
            return Err(GroupError::NoPendingCommit);
        }
        match &self.pending_self_update {
            Some(expected) if expected == &prepared.commit_bytes => Ok(()),
            Some(_) => Err(GroupError::PreparedCommitMismatch),
            None => Err(GroupError::NoPendingCommit),
        }
    }
}

/// Serialized outputs of an add-members commit, ready for delivery submission.
#[derive(Debug)]
pub struct AddMembersOutput {
    /// The commit `MlsMessageOut`, submitted as an `EnvelopeKind::Commit`.
    pub commit_bytes: Vec<u8>,
    /// The Welcome `MlsMessageOut`, submitted as an `EnvelopeKind::Welcome`
    /// addressed to the joiners' devices (ADR-0005 §1).
    pub welcome_bytes: Vec<u8>,
}

/// A locally prepared commit awaiting transport acceptance.
pub struct PreparedCommit {
    commit_bytes: Vec<u8>,
    proposed_epoch: u64,
}

impl PreparedCommit {
    /// Serialized commit for delivery as an `EnvelopeKind::Commit`.
    pub fn commit_bytes(&self) -> &[u8] {
        &self.commit_bytes
    }

    /// Epoch reached only after [`DmGroup::confirm_self_update`].
    pub fn proposed_epoch(&self) -> u64 {
        self.proposed_epoch
    }
}

/// Result of processing one incoming MLS message.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// Decrypted and unpadded application plaintext.
    Application(Vec<u8>),
    /// A verified staged commit was merged into this epoch.
    CommitMerged { epoch: u64 },
}
