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

/// Identifier for the log's signing key, carried in every tree head so a
/// client can select the matching pinned anchor before checking the
/// signature (ADR-0001 §5).
///
/// It is `SHA-256(log_ed25519_public_key)` — the RFC 6962 §3.2 LogID
/// construction (no novel crypto, INV-10). Because it is derived from the
/// key, the client needs no separate id registry: it maps each embedded
/// anchor to a `KeyId` by hashing the anchor once, then an STH verifies iff
/// its `key_id` names an embedded anchor *and* the signature checks under
/// that anchor. Carrying it in the signed input also binds each head to the
/// key that signed it, so a signature can never be re-presented as if made
/// under a different anchor. kt-log computes it via the crypto facade
/// (`sha256`); this module only carries the opaque bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(#[serde(with = "b64fixed32")] pub [u8; 32]);

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
        // The u16-BE length prefix fixes the handle's field boundary in the
        // signed leaf encoding. A handle >= 65_536 bytes would wrap the
        // prefix and make it lie about where `handle` ends — an
        // encoding-integrity footgun (docs/issues/004 F3) that becomes a
        // real ambiguity the moment any later leaf field turns
        // variable-width. auth-service caps handles at 64 bytes at
        // registration (ADR-0003 §6); this assert enforces the encoder's
        // side of that contract so a violation is caught in tests/debug
        // rather than silently corrupting the KT leaf.
        debug_assert!(
            handle.len() <= u16::MAX as usize,
            "KtLeaf handle exceeds u16 length prefix; auth-service must cap handle length (ADR-0003 §6)"
        );
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
    /// Identifies the anchor that signed this head; the client selects the
    /// matching pinned key by this id before verifying the signature
    /// (ADR-0001 §5). `SHA-256` of the log's Ed25519 public key.
    pub key_id: KeyId,
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// RFC 6962 Merkle root hash over all leaves.
    pub root_hash: KtHash,
    /// Unix seconds when this head was signed.
    pub timestamp: i64,
}

impl TreeHeadTbs {
    /// Deterministic bytes the log key signs: domain tag (u16-BE length ||
    /// bytes) || key_id (32B) || tree_size (u64-BE) || root_hash (32B) ||
    /// timestamp (i64-BE).
    ///
    /// `key_id` is inside the signed input on purpose: the signature then
    /// commits to which key made it, so a head cannot be relabelled under a
    /// different anchor (ADR-0001 §5).
    pub fn signing_input(&self) -> Vec<u8> {
        let tag = KT_TREE_HEAD_DOMAIN.as_bytes();
        let mut out = Vec::with_capacity(2 + tag.len() + 32 + 8 + 32 + 8);
        out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.key_id.0);
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

/// Response body of `GET /v1/kt/proof?leaf=<index>[&tree_size=<n>]`
/// (ADR-0003 §5): the inclusion proof **and** the exact signed tree head it
/// verifies against, returned together atomically.
///
/// The two must describe the same tree — kt-log's `verify_inclusion` rejects
/// a proof whose `tree_size` differs from the head's. Pairing them in one
/// response closes the TOCTOU window where the log grows between a
/// fetch-proof and a fetch-head call and the client is handed a proof and a
/// head that no longer match. The client verifies `proof` against
/// `signed_tree_head` under its pinned anchor (selected by
/// `signed_tree_head.tbs.key_id`); see docs/protocol/auth.md.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtProofResponse {
    pub proof: InclusionProof,
    pub signed_tree_head: SignedTreeHead,
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
                key_id: KeyId([5; 32]),
                tree_size: 7,
                root_hash: KtHash([9; 32]),
                timestamp: 1_700_000_000,
            },
            signature: Signature([3; 64]),
        };
        let json = serde_json::to_string(&sth).unwrap();
        let back: SignedTreeHead = serde_json::from_str(&json).unwrap();
        assert_eq!(sth, back);
        // Flattened TBS: fields (including key_id) appear at the top level.
        assert!(json.contains("\"tree_size\":7"));
        assert!(json.contains("\"key_id\":"));
    }

    #[test]
    fn tree_head_signing_input_pinned() {
        let tbs = TreeHeadTbs {
            key_id: KeyId([0xAB; 32]),
            tree_size: 1,
            root_hash: KtHash([0; 32]),
            timestamp: 2,
        };
        let input = tbs.signing_input();
        let tag = KT_TREE_HEAD_DOMAIN.as_bytes();
        // Layout: u16 tag len || tag || key_id(32) || tree_size(8) ||
        // root_hash(32) || timestamp(8).
        assert_eq!(input.len(), 2 + tag.len() + 32 + 8 + 32 + 8);
        let mut off = 2 + tag.len();
        assert_eq!(&input[off..off + 32], &[0xAB; 32]);
        off += 32;
        assert_eq!(&input[off..off + 8], &1u64.to_be_bytes());
    }

    #[test]
    fn key_id_is_covered_by_signing_input() {
        // Changing only key_id changes the signed bytes: the signature binds
        // the head to its signing key (ADR-0001 §5).
        let base = TreeHeadTbs {
            key_id: KeyId([1; 32]),
            tree_size: 3,
            root_hash: KtHash([7; 32]),
            timestamp: 99,
        };
        let mut other = base;
        other.key_id = KeyId([2; 32]);
        assert_ne!(base.signing_input(), other.signing_input());
    }

    #[test]
    fn kt_proof_response_roundtrip() {
        let resp = KtProofResponse {
            proof: InclusionProof {
                leaf_index: 2,
                tree_size: 5,
                audit_path: vec![KtHash([1; 32]), KtHash([2; 32])],
            },
            signed_tree_head: SignedTreeHead {
                tbs: TreeHeadTbs {
                    key_id: KeyId([4; 32]),
                    tree_size: 5,
                    root_hash: KtHash([8; 32]),
                    timestamp: 1_700_000_001,
                },
                signature: Signature([6; 64]),
            },
        };
        // Proof and head describe the same tree (ADR-0003 §5 invariant).
        assert_eq!(resp.proof.tree_size, resp.signed_tree_head.tbs.tree_size);
        let json = serde_json::to_string(&resp).unwrap();
        let back: KtProofResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
        assert!(json.contains("\"proof\":"));
        assert!(json.contains("\"signed_tree_head\":"));
    }
}
