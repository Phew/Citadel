//! Pure RFC 6962 Merkle tree algorithms (hashing, roots, proofs).
//!
//! Everything here is a pure function over leaf hashes: no storage, no
//! signatures, no I/O. Algorithms follow RFC 6962 §2.1 (generation) and
//! RFC 9162 §2.1.3.2 / §2.1.4.2 (verification) exactly; do not "optimize"
//! them — auditors diff this file against the RFC text.
//!
//! Hashing is SHA-256 via the citadel-service-crypto facade (INV-10):
//!   leaf hash  = SHA-256(0x00 || leaf_bytes)
//!   node hash  = SHA-256(0x01 || left || right)
//! Domain-separating leaves from nodes prevents second-preimage attacks
//! (a leaf that encodes an internal node).

use citadel_service_crypto::sha256;

/// A 32-byte SHA-256 Merkle hash.
pub type Hash = [u8; 32];

/// RFC 6962 leaf hash: `SHA-256(0x00 || leaf_bytes)`.
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut input = Vec::with_capacity(1 + leaf_bytes.len());
    input.push(0x00);
    input.extend_from_slice(leaf_bytes);
    sha256(&input)
}

/// RFC 6962 node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut input = Vec::with_capacity(1 + 64);
    input.push(0x01);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

/// Largest power of two strictly less than `n`. Precondition: `n >= 2`.
fn split_point(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Merkle Tree Hash over `leaves[0..n]` (RFC 6962 §2.1). The root of the
/// empty tree is `SHA-256("")`.
pub fn root_hash(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(b""),
        1 => leaves[0],
        n => {
            let k = split_point(n as u64) as usize;
            node_hash(&root_hash(&leaves[..k]), &root_hash(&leaves[k..]))
        }
    }
}

/// Audit path for `leaves[index]` within the tree over all of `leaves`
/// (RFC 6962 §2.1.1 PATH). Returns leaf-to-root sibling hashes.
///
/// Precondition: `index < leaves.len()`; panics otherwise (caller bug, not
/// input validation — the log validates indices before calling).
pub fn inclusion_path(index: u64, leaves: &[Hash]) -> Vec<Hash> {
    assert!(
        (index as usize) < leaves.len(),
        "inclusion_path: index out of range"
    );
    let n = leaves.len() as u64;
    if n == 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if index < k {
        let mut path = inclusion_path(index, &leaves[..k as usize]);
        path.push(root_hash(&leaves[k as usize..]));
        path
    } else {
        let mut path = inclusion_path(index - k, &leaves[k as usize..]);
        path.push(root_hash(&leaves[..k as usize]));
        path
    }
}

/// Consistency proof between the tree over `leaves[0..first]` and the tree
/// over all of `leaves` (RFC 6962 §2.1.2 PROOF).
///
/// Precondition: `0 < first <= leaves.len()`; panics otherwise.
pub fn consistency_path(first: u64, leaves: &[Hash]) -> Vec<Hash> {
    assert!(
        first > 0 && (first as usize) <= leaves.len(),
        "consistency_path: first out of range"
    );
    subproof(first, leaves, true)
}

/// RFC 6962 SUBPROOF.
fn subproof(m: u64, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    let n = leaves.len() as u64;
    if m == n {
        if complete {
            return Vec::new();
        }
        return vec![root_hash(leaves)];
    }
    let k = split_point(n);
    if m <= k {
        let mut path = subproof(m, &leaves[..k as usize], complete);
        path.push(root_hash(&leaves[k as usize..]));
        path
    } else {
        let mut path = subproof(m - k, &leaves[k as usize..], false);
        path.push(root_hash(&leaves[..k as usize]));
        path
    }
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2). Returns true iff
/// `leaf` at `leaf_index` is proven under `root` for a tree of `tree_size`.
pub fn verify_inclusion(
    leaf: &Hash,
    leaf_index: u64,
    tree_size: u64,
    path: &[Hash],
    root: &Hash,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf;
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                // Right-shift until LSB(fnode) set or fnode == 0.
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

/// Verify a consistency proof between `(first, first_root)` and
/// `(second, second_root)` (RFC 9162 §2.1.4.2). Returns true iff the second
/// tree is an append-only extension of the first.
pub fn verify_consistency(
    first: u64,
    second: u64,
    path: &[Hash],
    first_root: &Hash,
    second_root: &Hash,
) -> bool {
    if first > second {
        return false;
    }
    // Degenerate cases: the empty tree is a prefix of everything; a tree is
    // consistent with itself iff the roots match. Both take an empty path.
    if first == 0 {
        return path.is_empty();
    }
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    if path.is_empty() {
        return false;
    }

    // If first is an exact power of two, first_root is implicitly the first
    // proof component.
    let mut path_iter = path.iter();
    let (mut fr, mut sr) = if first.is_power_of_two() {
        (*first_root, *first_root)
    } else {
        let p = *path_iter.next().expect("checked non-empty");
        (p, p)
    };

    let mut fnode = first - 1;
    let mut snode = second - 1;
    // Right-shift both while LSB(fnode) is set.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    for p in path_iter {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }

    snode == 0 && &fr == first_root && &sr == second_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Hash {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    /// RFC 6962 / Certificate Transparency reference test leaves
    /// (from the CT Go implementation's merkle tree test vectors).
    fn ct_leaves() -> Vec<Hash> {
        [
            &[][..],
            &[0x00],
            &[0x10],
            &[0x20, 0x21],
            &[0x30, 0x31],
            &[0x40, 0x41, 0x42, 0x43],
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            &[
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f,
            ],
        ]
        .iter()
        .map(|l| leaf_hash(l))
        .collect()
    }

    #[test]
    fn empty_tree_root_is_sha256_of_empty_string() {
        assert_eq!(
            root_hash(&[]),
            h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn ct_reference_roots() {
        let leaves = ct_leaves();
        // Golden roots from the Certificate Transparency reference implementation.
        assert_eq!(
            root_hash(&leaves[..1]),
            h("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        );
        assert_eq!(
            root_hash(&leaves[..2]),
            h("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")
        );
        assert_eq!(
            root_hash(&leaves[..3]),
            h("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77")
        );
        assert_eq!(
            root_hash(&leaves[..7]),
            h("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c")
        );
        assert_eq!(
            root_hash(&leaves[..8]),
            h("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")
        );
    }

    #[test]
    fn inclusion_all_indices_all_sizes() {
        let leaves = ct_leaves();
        for size in 1..=leaves.len() {
            let root = root_hash(&leaves[..size]);
            for idx in 0..size {
                let path = inclusion_path(idx as u64, &leaves[..size]);
                assert!(
                    verify_inclusion(&leaves[idx], idx as u64, size as u64, &path, &root),
                    "inclusion failed for idx {idx} size {size}"
                );
                // Wrong leaf must fail.
                let wrong = leaf_hash(b"not-in-tree");
                assert!(!verify_inclusion(
                    &wrong,
                    idx as u64,
                    size as u64,
                    &path,
                    &root
                ));
            }
        }
    }

    #[test]
    fn inclusion_rejects_tampered_path_and_wrong_index() {
        let leaves = ct_leaves();
        let root = root_hash(&leaves);
        let path = inclusion_path(3, &leaves);
        // Tampered path element.
        let mut bad = path.clone();
        bad[0][0] ^= 0x01;
        assert!(!verify_inclusion(&leaves[3], 3, 8, &bad, &root));
        // Wrong index for same proof.
        assert!(!verify_inclusion(&leaves[3], 2, 8, &path, &root));
        // Index out of range.
        assert!(!verify_inclusion(&leaves[3], 9, 8, &path, &root));
    }

    #[test]
    fn consistency_all_size_pairs() {
        let leaves = ct_leaves();
        for second in 1..=leaves.len() {
            let second_root = root_hash(&leaves[..second]);
            for first in 1..=second {
                let first_root = root_hash(&leaves[..first]);
                let path = consistency_path(first as u64, &leaves[..second]);
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &path,
                        &first_root,
                        &second_root
                    ),
                    "consistency failed for {first} -> {second}"
                );
            }
        }
    }

    #[test]
    fn consistency_rejects_forked_history() {
        let leaves = ct_leaves();
        let first_root = root_hash(&leaves[..4]);
        // A "log" that rewrote leaf 2 after signing the size-4 head.
        let mut forked = leaves.clone();
        forked[2] = leaf_hash(b"rewritten");
        let forked_root = root_hash(&forked);
        let forked_path = consistency_path(4, &forked);
        assert!(!verify_consistency(
            4,
            8,
            &forked_path,
            &first_root,
            &forked_root
        ));
    }

    #[test]
    fn consistency_degenerate_cases() {
        let leaves = ct_leaves();
        let root = root_hash(&leaves);
        // Empty first tree is a prefix of anything (empty path only).
        assert!(verify_consistency(0, 8, &[], &root_hash(&[]), &root));
        assert!(!verify_consistency(0, 8, &[root], &root_hash(&[]), &root));
        // Same size: roots must match, path must be empty.
        assert!(verify_consistency(8, 8, &[], &root, &root));
        assert!(!verify_consistency(
            8,
            8,
            &[],
            &root_hash(&leaves[..4]),
            &root
        ));
        // first > second is always invalid.
        assert!(!verify_consistency(9, 8, &[], &root, &root));
    }
}
