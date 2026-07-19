//! Append-only key transparency log (M1, F1).
//!
//! An RFC 6962 Merkle tree over [`citadel_proto::kt::KtLeaf`] encodings, with
//! Ed25519-signed tree heads, inclusion proofs, and consistency proofs.
//! Wire shapes live in citadel-proto; this crate owns the algorithms
//! ([`tree`]) and the log/signing structure below.
//!
//! Trust model: the server operates the log, clients verify it (INV-4). A
//! client trusts a credential's identity key only after (a) the STH signature
//! verifies against the pinned log public key, (b) the leaf's inclusion proof
//! verifies against that STH, and (c) successive STHs verify consistency
//! (append-only). The server signing dishonest heads is detectable, not
//! preventable — that is the KT design point.
//!
//! Signing note (AGENTS.md rule 6): tree-head signing is deliberately
//! encapsulated here as [`TreeHeadSigner`], which signs *only*
//! `TreeHeadTbs::signing_input()`. auth-service consumes this crate and thus
//! never gains a general-purpose signing capability; the service crypto
//! facade stays verify/sha256/random only. Recorded in ADR-0001.

pub mod tree;

use citadel_proto::credential::Signature;
use citadel_proto::kt::{
    ConsistencyProof, InclusionProof, KeyId, KtHash, KtLeaf, SignedTreeHead, TreeHeadTbs,
};
use ed25519_dalek::{Signer, SigningKey};
use tree::Hash;

/// Errors from log operations. Proof *verification* failures are `false`
/// returns, not errors: an invalid proof is an expected adversarial input.
#[derive(Debug, thiserror::Error)]
pub enum KtLogError {
    #[error("leaf index {index} out of range for tree size {tree_size}")]
    LeafOutOfRange { index: u64, tree_size: u64 },
    #[error("requested tree size {requested} exceeds current size {current}")]
    SizeOutOfRange { requested: u64, current: u64 },
    #[error("first size {first} must be > 0 and <= second size {second}")]
    InvalidSizeRange { first: u64, second: u64 },
}

/// The append-only log: an in-memory sequence of leaf hashes.
///
/// Persistence strategy (M1): auth-service stores the full leaf *bytes* in
/// `kt_log` (PostgreSQL, append-only) and rebuilds this structure at startup
/// by replaying them in sequence order. The in-memory tree is the proof
/// engine, Postgres is the durability layer. Rebuild is O(n) hashes and the
/// root must match the last persisted signed tree head — a mismatch at
/// startup is fatal (evidence of tampering or corruption).
#[derive(Clone, Debug, Default)]
pub struct KtLog {
    leaf_hashes: Vec<Hash>,
}

impl KtLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from previously persisted leaf bytes, in append order.
    pub fn from_leaf_bytes<'a>(leaves: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self {
            leaf_hashes: leaves.into_iter().map(tree::leaf_hash).collect(),
        }
    }

    /// Number of leaves.
    pub fn size(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    /// Append a leaf, returning its index. This is the ONLY mutation this
    /// type offers: no update, no delete, no truncate (append-only invariant).
    pub fn append(&mut self, leaf: &KtLeaf) -> u64 {
        let index = self.size();
        self.leaf_hashes.push(tree::leaf_hash(&leaf.leaf_bytes()));
        index
    }

    /// Current Merkle root.
    pub fn root(&self) -> Hash {
        tree::root_hash(&self.leaf_hashes)
    }

    /// Root of the historical tree at `tree_size`.
    pub fn root_at(&self, tree_size: u64) -> Result<Hash, KtLogError> {
        if tree_size > self.size() {
            return Err(KtLogError::SizeOutOfRange {
                requested: tree_size,
                current: self.size(),
            });
        }
        Ok(tree::root_hash(&self.leaf_hashes[..tree_size as usize]))
    }

    /// Inclusion proof for `leaf_index` against the tree at `tree_size`.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, KtLogError> {
        if tree_size > self.size() {
            return Err(KtLogError::SizeOutOfRange {
                requested: tree_size,
                current: self.size(),
            });
        }
        if leaf_index >= tree_size {
            return Err(KtLogError::LeafOutOfRange {
                index: leaf_index,
                tree_size,
            });
        }
        let path = tree::inclusion_path(leaf_index, &self.leaf_hashes[..tree_size as usize]);
        Ok(InclusionProof {
            leaf_index,
            tree_size,
            audit_path: path.into_iter().map(KtHash).collect(),
        })
    }

    /// Consistency proof from `first_tree_size` to `second_tree_size`.
    pub fn consistency_proof(
        &self,
        first_tree_size: u64,
        second_tree_size: u64,
    ) -> Result<ConsistencyProof, KtLogError> {
        if second_tree_size > self.size() {
            return Err(KtLogError::SizeOutOfRange {
                requested: second_tree_size,
                current: self.size(),
            });
        }
        if first_tree_size == 0 || first_tree_size > second_tree_size {
            return Err(KtLogError::InvalidSizeRange {
                first: first_tree_size,
                second: second_tree_size,
            });
        }
        let path = tree::consistency_path(
            first_tree_size,
            &self.leaf_hashes[..second_tree_size as usize],
        );
        Ok(ConsistencyProof {
            first_tree_size,
            second_tree_size,
            path: path.into_iter().map(KtHash).collect(),
        })
    }
}

/// Signs tree heads, and nothing else. Wraps the log's Ed25519 key so the
/// consuming service cannot sign arbitrary bytes: the input is always
/// `TreeHeadTbs::signing_input()` built here.
pub struct TreeHeadSigner {
    key: SigningKey,
}

impl TreeHeadSigner {
    /// Construct from the log's 32-byte Ed25519 seed (loaded by auth-service
    /// from its secret store; never logged, never sent on the wire — this is
    /// a server operational key, not user key material).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The log's public key, for client pinning and STH verification.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// This key's `KeyId` = `SHA-256(public_key)` (ADR-0001 §5, RFC 6962
    /// LogID). Stamped into every head this signer produces, and the value a
    /// client derives from its pinned anchor to match against `tbs.key_id`.
    /// SHA-256 comes from the crypto facade (no primitive dep in kt-log's
    /// hashing path beyond tree-node hashing).
    pub fn key_id(&self) -> KeyId {
        KeyId(key_id_of(&self.public_key()))
    }

    /// Sign a tree head for `log` at its current size.
    pub fn sign_head(&self, log: &KtLog, timestamp: i64) -> SignedTreeHead {
        let tbs = TreeHeadTbs {
            key_id: self.key_id(),
            tree_size: log.size(),
            root_hash: KtHash(log.root()),
            timestamp,
        };
        let sig = self.key.sign(&tbs.signing_input());
        SignedTreeHead {
            tbs,
            signature: Signature(sig.to_bytes()),
        }
    }
}

/// `KeyId` bytes for an Ed25519 public key: `SHA-256(public_key)` via the
/// crypto facade (ADR-0001 §5).
pub fn key_id_of(public_key: &[u8; 32]) -> [u8; 32] {
    citadel_service_crypto::sha256(public_key)
}

// ---------- Client-side verification (pure; used by citadel-core and tests) ----------

/// Verify an STH against a pinned log public key. Two-part check per
/// ADR-0001 §5: the head's `key_id` must name this anchor
/// (`SHA-256(log_public_key)`), *and* the signature must verify under it.
/// The `key_id` gate lets a client with an anchor *set* pick the right key
/// up front, and rejects a head aimed at some other anchor before the
/// signature check even runs.
pub fn verify_tree_head(sth: &SignedTreeHead, log_public_key: &[u8; 32]) -> bool {
    if sth.tbs.key_id.0 != key_id_of(log_public_key) {
        return false;
    }
    citadel_service_crypto::verify(log_public_key, &sth.tbs.signing_input(), &sth.signature.0)
        .is_ok()
}

/// Verify that `leaf` is included under `sth`. The proof's tree_size must
/// match the STH's — a proof against a different (even larger) tree proves
/// nothing about this head.
pub fn verify_inclusion(leaf: &KtLeaf, proof: &InclusionProof, sth: &SignedTreeHead) -> bool {
    if proof.tree_size != sth.tbs.tree_size {
        return false;
    }
    let path: Vec<Hash> = proof.audit_path.iter().map(|h| h.0).collect();
    tree::verify_inclusion(
        &tree::leaf_hash(&leaf.leaf_bytes()),
        proof.leaf_index,
        proof.tree_size,
        &path,
        &sth.tbs.root_hash.0,
    )
}

/// Verify that `newer` extends `older` append-only, via `proof`.
pub fn verify_consistency(
    older: &SignedTreeHead,
    newer: &SignedTreeHead,
    proof: &ConsistencyProof,
) -> bool {
    if proof.first_tree_size != older.tbs.tree_size || proof.second_tree_size != newer.tbs.tree_size
    {
        return false;
    }
    let path: Vec<Hash> = proof.path.iter().map(|h| h.0).collect();
    tree::verify_consistency(
        proof.first_tree_size,
        proof.second_tree_size,
        &path,
        &older.tbs.root_hash.0,
        &newer.tbs.root_hash.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_proto::credential::IdentityPublicKey;
    use citadel_proto::ids::AccountId;
    use uuid::Uuid;

    fn leaf(i: u8) -> KtLeaf {
        KtLeaf {
            account_id: AccountId::from_uuid(Uuid::from_bytes([i; 16])),
            handle: format!("user-{i}"),
            identity_pubkey: IdentityPublicKey([i; 32]),
            appended_at: i64::from(i),
        }
    }

    fn signer() -> TreeHeadSigner {
        TreeHeadSigner::from_seed(&[42u8; 32])
    }

    #[test]
    fn registration_flow_end_to_end() {
        // F1: append identity, sign head, client verifies own inclusion.
        let mut log = KtLog::new();
        let s = signer();
        let l = leaf(1);
        let idx = log.append(&l);
        let sth = s.sign_head(&log, 1_700_000_000);

        assert!(verify_tree_head(&sth, &s.public_key()));
        let proof = log.inclusion_proof(idx, log.size()).unwrap();
        assert!(verify_inclusion(&l, &proof, &sth));

        // Wrong pinned key must fail.
        assert!(!verify_tree_head(&sth, &[0u8; 32]));
        // A different leaf must not verify under this proof.
        assert!(!verify_inclusion(&leaf(2), &proof, &sth));
    }

    #[test]
    fn consistency_across_appends() {
        let mut log = KtLog::new();
        let s = signer();
        for i in 0..5 {
            log.append(&leaf(i));
        }
        let old_sth = s.sign_head(&log, 100);
        for i in 5..9 {
            log.append(&leaf(i));
        }
        let new_sth = s.sign_head(&log, 200);

        let proof = log.consistency_proof(5, 9).unwrap();
        assert!(verify_consistency(&old_sth, &new_sth, &proof));

        // Proof for mismatched sizes is rejected up front.
        let bad = log.consistency_proof(4, 9).unwrap();
        assert!(!verify_consistency(&old_sth, &new_sth, &bad));
    }

    #[test]
    fn proof_tree_size_must_match_sth() {
        let mut log = KtLog::new();
        let s = signer();
        let l = leaf(1);
        log.append(&l);
        let sth_at_1 = s.sign_head(&log, 100);
        log.append(&leaf(2));
        // Proof at size 2 must not verify against the size-1 STH.
        let proof = log.inclusion_proof(0, 2).unwrap();
        assert!(!verify_inclusion(&l, &proof, &sth_at_1));
    }

    #[test]
    fn rebuild_from_persisted_bytes_matches() {
        let mut log = KtLog::new();
        let leaves: Vec<KtLeaf> = (0..7).map(leaf).collect();
        for l in &leaves {
            log.append(l);
        }
        let bytes: Vec<Vec<u8>> = leaves.iter().map(|l| l.leaf_bytes()).collect();
        let rebuilt = KtLog::from_leaf_bytes(bytes.iter().map(Vec::as_slice));
        assert_eq!(rebuilt.root(), log.root());
        assert_eq!(rebuilt.size(), log.size());
    }

    #[test]
    fn sign_head_stamps_key_id_of_public_key() {
        let mut log = KtLog::new();
        let s = signer();
        log.append(&leaf(1));
        let sth = s.sign_head(&log, 1);
        // The head carries SHA-256(public_key), and it verifies.
        assert_eq!(sth.tbs.key_id, s.key_id());
        assert_eq!(sth.tbs.key_id.0, key_id_of(&s.public_key()));
        assert!(verify_tree_head(&sth, &s.public_key()));
    }

    #[test]
    fn verify_rejects_key_id_that_names_another_anchor() {
        let mut log = KtLog::new();
        let s = signer();
        log.append(&leaf(1));
        let mut sth = s.sign_head(&log, 1);
        // Corrupt only the key_id so it no longer names this anchor: rejected
        // at the key_id gate (the signature would also fail, but the gate
        // fires first — a client with the wrong pinned key stops here).
        sth.tbs.key_id.0[0] ^= 0xFF;
        assert!(!verify_tree_head(&sth, &s.public_key()));
    }

    #[test]
    fn out_of_range_requests_are_errors() {
        let mut log = KtLog::new();
        log.append(&leaf(1));
        assert!(log.inclusion_proof(1, 1).is_err());
        assert!(log.inclusion_proof(0, 2).is_err());
        assert!(log.consistency_proof(0, 1).is_err());
        assert!(log.consistency_proof(1, 2).is_err());
        assert!(log.root_at(2).is_err());
    }
}
