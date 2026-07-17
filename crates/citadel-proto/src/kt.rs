//! Key transparency wire types (F1, M1).
//!
//! Shapes follow RFC 6962 (Certificate Transparency): an append-only Merkle
//! tree over identity-key bindings, signed tree heads, inclusion proofs, and
//! consistency proofs. Hashing and proof *algorithms* live in the `kt-log`
//! crate; this module owns only the byte encodings and JSON shapes, so
//! clients and the auth-service verify against one contract (INV-4).

use crate::bytes::b64fixed32;
use crate::credential::{IdentityPublicKey, Signature};
use crate::ids::AccountId;
use serde::{Deserialize, Serialize};

/// Domain separation tag for tree-head signatures.
pub const KT_TREE_HEAD_DOMAIN: &str = "citadel/v1/kt-tree-head";

/// Domain separation tag for leaf byte encodings (input to the RFC 6962
/// `0x00 || leaf` hash performed by kt-log).
pub const KT_LEAF_DOMAIN: &str = "citadel/v1/kt-leaf";

/// A 32-byte Merkle node/root hash (SHA-256).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KtHash(#[serde(with = "b64fixed32")] pub [u8; 32]);

/// The content of one KT log leaf: a binding of an account to an identity key.
/// Appended at registration; identity-key rotation (post-v1) appends a new leaf,
/// never mutates an old one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtLeaf {
    pub account_id: AccountId,
    /// UTF-8 handle at registration time. Informational for audit; the
    /// authoritative binding is account_id -> identity_pubkey.
    pub handle: String,
    pub identity_pubkey: IdentityPublicKey,
    /// Unix seconds at append time (set by auth-service).
    pub appended_at: i64,
}

impl KtLeaf {
    /// Deterministic leaf bytes: domain tag (u16-BE length || bytes),
    /// account_id (16B), handle (u16-BE length || UTF-8 bytes),
    /// identity_pubkey (32B), appended_at (i64-BE).
    ///
    /// kt-log hashes these as `SHA-256(0x00 || leaf_bytes)` per RFC 6962.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let tag = KT_LEAF_DOMAIN.as_bytes();
        let handle = self.handle.as_bytes();
        let mut out = Vec::with_capacity(2 + tag.len() + 16 + 2 + handle.len() + 32 + 8);
        out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(self.account_id.as_uuid().as_bytes());
        out.extend_from_slice(&(handle.len() as u16).to_be_bytes());
        out.extend_from_slice(handle);
        out.extend_from_slice(&self.identity_pubkey.0);
        out.extend_from_slice(&self.appended_at.to_be_bytes());
        out
    }
}

/// The signed portion of a tree head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHeadTbs {
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// RFC 6962 Merkle root hash over all leaves.
    pub root_hash: KtHash,
    /// Unix seconds when this head was signed.
    pub timestamp: i64,
}

impl TreeHeadTbs {
    /// Deterministic bytes the log key signs: domain tag (u16-BE length ||
    /// bytes) || tree_size (u64-BE) || root_hash (32B) || timestamp (i64-BE).
    pub fn signing_input(&self) -> Vec<u8> {
        let tag = KT_TREE_HEAD_DOMAIN.as_bytes();
        let mut out = Vec::with_capacity(2 + tag.len() + 8 + 32 + 8);
        out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        out.extend_from_slice(&self.root_hash.0);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out
    }
}

/// A signed tree head (STH). `GET /v1/kt/tree-head`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    #[serde(flatten)]
    pub tbs: TreeHeadTbs,
    /// Ed25519 signature by the log's public key over `tbs.signing_input()`.
    pub signature: Signature,
}

/// Merkle inclusion proof for one leaf against a tree head
/// (`GET /v1/kt/proof?leaf=...`). Path is leaf-to-root sibling hashes,
/// RFC 6962 §2.1.1 ordering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    /// Size of the tree this proof verifies against (must match an STH).
    pub tree_size: u64,
    pub audit_path: Vec<KtHash>,
}

/// Merkle consistency proof between two tree sizes (RFC 6962 §2.1.2).
/// Clients use this to detect history rewrites between polled STHs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub first_tree_size: u64,
    pub second_tree_size: u64,
    pub path: Vec<KtHash>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn leaf_bytes_deterministic_and_distinct() {
        let leaf = KtLeaf {
            account_id: AccountId::from_uuid(Uuid::from_bytes([1; 16])),
            handle: "alice".into(),
            identity_pubkey: IdentityPublicKey([2; 32]),
            appended_at: 42,
        };
        assert_eq!(leaf.leaf_bytes(), leaf.leaf_bytes());

        let mut other = leaf.clone();
        other.handle = "alicf".into();
        assert_ne!(leaf.leaf_bytes(), other.leaf_bytes());
    }

    #[test]
    fn handle_length_prefix_prevents_field_smearing() {
        // "ab" + pubkey starting with 'c'... must not collide with "abc" + shifted bytes:
        // the u16 length prefix fixes field boundaries.
        let a = KtLeaf {
            account_id: AccountId::from_uuid(Uuid::from_bytes([1; 16])),
            handle: "ab".into(),
            identity_pubkey: IdentityPublicKey([b'c'; 32]),
            appended_at: 0,
        };
        let b = KtLeaf {
            account_id: AccountId::from_uuid(Uuid::from_bytes([1; 16])),
            handle: "abc".into(),
            identity_pubkey: IdentityPublicKey([b'c'; 32]),
            appended_at: 0,
        };
        assert_ne!(a.leaf_bytes(), b.leaf_bytes());
    }

    #[test]
    fn sth_json_roundtrip() {
        let sth = SignedTreeHead {
            tbs: TreeHeadTbs {
                tree_size: 7,
                root_hash: KtHash([9; 32]),
                timestamp: 1_700_000_000,
            },
            signature: Signature([3; 64]),
        };
        let json = serde_json::to_string(&sth).unwrap();
        let back: SignedTreeHead = serde_json::from_str(&json).unwrap();
        assert_eq!(sth, back);
        // Flattened TBS: fields appear at the top level of the JSON object.
        assert!(json.contains("\"tree_size\":7"));
    }

    #[test]
    fn tree_head_signing_input_pinned() {
        let tbs = TreeHeadTbs {
            tree_size: 1,
            root_hash: KtHash([0; 32]),
            timestamp: 2,
        };
        let input = tbs.signing_input();
        let tag = KT_TREE_HEAD_DOMAIN.as_bytes();
        assert_eq!(input.len(), 2 + tag.len() + 8 + 32 + 8);
        assert_eq!(
            &input[2 + tag.len()..2 + tag.len() + 8],
            &1u64.to_be_bytes()
        );
    }
}
