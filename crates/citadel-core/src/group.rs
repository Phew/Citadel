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
    #[error("message was not an application message")]
    NotApplication,
}

/// A joined DM group. Wraps the OpenMLS group; all mutation goes through here so
/// padding and member verification cannot be bypassed.
pub struct DmGroup {
    mls: MlsGroup,
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
        Ok(Self { mls })
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
    ) -> Result<AddMembersOutput, GroupError> {
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
            verify_member_credential(member.credential.serialized_content(), verifier)?;
        }

        let mls = staged
            .into_group(provider)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        Ok(Self { mls })
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

    /// Decrypt an incoming application message (F4 receive), returning the
    /// unpadded plaintext. `message_bytes` is a serialized `MlsMessageIn`.
    /// Non-application messages (proposals/commits) return
    /// [`GroupError::NotApplication`] — handling those is M3.
    pub fn receive(
        &mut self,
        provider: &Provider,
        message_bytes: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(message_bytes)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|_| GroupError::NotApplication)?;
        let processed = self
            .mls
            .process_message(provider, protocol)
            .map_err(|e| GroupError::Mls(format!("{e:?}")))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(unpad(&app.into_bytes())?),
            _ => Err(GroupError::NotApplication),
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
}

/// Serialized outputs of an add-members commit, ready for delivery submission.
pub struct AddMembersOutput {
    /// The commit `MlsMessageOut`, submitted as an `EnvelopeKind::Commit`.
    pub commit_bytes: Vec<u8>,
    /// The Welcome `MlsMessageOut`, submitted as an `EnvelopeKind::Welcome`
    /// addressed to the joiners' devices (ADR-0005 §1).
    pub welcome_bytes: Vec<u8>,
}
