//! The production key-transparency verifier (INV-4).
//!
//! A peer's identity key is trusted only after this verifier has: fetched a
//! signed tree head and verified its signature under the embedded log anchor;
//! proved that head is consistent with the persisted checkpoint (ADR-0001's
//! anti-rollback rule, so a server cannot show this client a forked log);
//! recorded the head as the new checkpoint; fetched the peer's inclusion
//! proof against that exact head; and verified it. Only then does
//! `is_kt_attested` answer true, and the peer row is persisted so a restart
//! does not lose the attestation.
//!
//! Leaf coordinates come from the server (`GET /v1/kt/leaf`) as a hint. The
//! proof is what is trusted; a wrong hint simply fails to verify.

use crate::error::AppError;
use crate::transport::AuthApi;
use citadel_core::credential::IdentityVerifier;
use citadel_core::store::{KtCheckpoint, LocalStore, OperationId, PeerRow};
use citadel_proto::credential::IdentityPublicKey;
use citadel_proto::ids::AccountId;
use citadel_proto::kt::{KeyId, KtHash, KtLeafInfo, SignedTreeHead, TreeHeadTbs};
use citadel_proto::Signature;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

pub struct KtVerifier {
    auth: AuthApi,
    anchor: [u8; 32],
    store: Arc<LocalStore>,
    attested: RwLock<HashSet<(AccountId, [u8; 32])>>,
}

impl KtVerifier {
    /// Load the durable attestations, so peers verified in an earlier session
    /// are attested in this one without a network round trip.
    pub fn new(auth: AuthApi, anchor: [u8; 32], store: Arc<LocalStore>) -> Result<Self, AppError> {
        let attested = store
            .peers()?
            .into_iter()
            .map(|peer| (peer.account_id, peer.identity_pubkey))
            .collect();
        Ok(Self {
            auth,
            anchor,
            store,
            attested: RwLock::new(attested),
        })
    }

    pub fn anchor(&self) -> [u8; 32] {
        self.anchor
    }

    /// Fetch the latest head, verify it, prove it consistent with the
    /// checkpoint, and advance the checkpoint. Returns the head every proof in
    /// this round must be checked against.
    pub async fn verified_head(&self) -> Result<SignedTreeHead, AppError> {
        let head = self.auth.tree_head().await?;
        self.accept_head(head).await
    }

    /// Verify and checkpoint a head obtained elsewhere (registration returns
    /// one), so it goes through exactly the same checks as a fetched one.
    pub async fn accept_head(&self, head: SignedTreeHead) -> Result<SignedTreeHead, AppError> {
        if !kt_log::verify_tree_head(&head, &self.anchor) {
            return Err(AppError::KtVerification(
                "tree head signature does not verify under the embedded log anchor".into(),
            ));
        }
        match self.store.kt_checkpoint()? {
            None => {}
            Some(checkpoint) => self.check_against_checkpoint(&checkpoint, &head).await?,
        }
        self.store.accept_kt_head(
            OperationId::generate()?,
            head.tbs.tree_size,
            head.tbs.root_hash.0.to_vec(),
        )?;
        Ok(head)
    }

    async fn check_against_checkpoint(
        &self,
        checkpoint: &KtCheckpoint,
        head: &SignedTreeHead,
    ) -> Result<(), AppError> {
        let checkpoint_root: [u8; 32] =
            checkpoint.root_hash.as_slice().try_into().map_err(|_| {
                AppError::KtVerification("persisted checkpoint root is not 32 bytes".into())
            })?;
        if head.tbs.tree_size < checkpoint.tree_size {
            return Err(AppError::KtVerification(format!(
                "server presented tree size {} below the checkpoint {}: rollback or fork",
                head.tbs.tree_size, checkpoint.tree_size
            )));
        }
        if head.tbs.tree_size == checkpoint.tree_size {
            if head.tbs.root_hash.0 != checkpoint_root {
                return Err(AppError::KtVerification(
                    "server presented a different root at the checkpoint size: fork".into(),
                ));
            }
            return Ok(());
        }
        let proof = self
            .auth
            .consistency(checkpoint.tree_size, head.tbs.tree_size)
            .await?;
        // Only tree_size and root_hash of the older head are read by the
        // verifier; the checkpoint stores exactly those.
        let older = SignedTreeHead {
            tbs: TreeHeadTbs {
                key_id: KeyId(kt_log::key_id_of(&self.anchor)),
                tree_size: checkpoint.tree_size,
                root_hash: KtHash(checkpoint_root),
                timestamp: 0,
            },
            signature: Signature([0; 64]),
        };
        if !kt_log::verify_consistency(&older, head, &proof) {
            return Err(AppError::KtVerification(format!(
                "consistency proof from {} to {} does not verify: fork",
                checkpoint.tree_size, head.tbs.tree_size
            )));
        }
        Ok(())
    }

    /// Verify a peer's inclusion under a verified head and record it.
    pub async fn attest(&self, info: &KtLeafInfo) -> Result<(), AppError> {
        let head = self.verified_head().await?;
        self.attest_under(info, &head).await
    }

    pub async fn attest_under(
        &self,
        info: &KtLeafInfo,
        head: &SignedTreeHead,
    ) -> Result<(), AppError> {
        let response = self.auth.proof(info.leaf_index, head.tbs.tree_size).await?;
        if response.signed_tree_head != *head {
            return Err(AppError::KtVerification(
                "proof response carries a different tree head than the one verified".into(),
            ));
        }
        let leaf = info.to_leaf();
        if !kt_log::verify_inclusion(&leaf, &response.proof, head) {
            return Err(AppError::KtVerification(format!(
                "inclusion proof for {} (leaf {}) does not verify",
                info.handle, info.leaf_index
            )));
        }
        self.store.upsert_peer(PeerRow {
            account_id: info.account_id,
            handle: info.handle.clone(),
            identity_pubkey: info.identity_pubkey.0,
            kt_leaf_index: info.leaf_index,
            kt_appended_at: info.appended_at,
            attested_tree_size: head.tbs.tree_size,
        })?;
        self.attested
            .write()
            .expect("attested set poisoned")
            .insert((info.account_id, info.identity_pubkey.0));
        Ok(())
    }

    /// Resolve a handle to KT-verified coordinates. The identity key returned
    /// is attested by the time this returns.
    pub async fn lookup_handle(&self, handle: &str) -> Result<KtLeafInfo, AppError> {
        let info = self.auth.leaf_by_handle(handle).await?;
        self.attest(&info).await?;
        Ok(info)
    }

    pub async fn lookup_account(&self, account: AccountId) -> Result<KtLeafInfo, AppError> {
        let info = self.auth.leaf_by_account(account).await?;
        self.attest(&info).await?;
        Ok(info)
    }
}

impl IdentityVerifier for KtVerifier {
    fn is_kt_attested(&self, account_id: AccountId, identity_pubkey: &IdentityPublicKey) -> bool {
        self.attested
            .read()
            .expect("attested set poisoned")
            .contains(&(account_id, identity_pubkey.0))
    }
}
