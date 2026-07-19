//! Independent-oracle cross-check for the RFC 6962 Merkle algorithms
//! (PLAN.md §13: "an independent oracle where one exists (e.g. the Go oracle
//! pattern for Merkle structures)").
//!
//! The fixtures in `tests/fixtures/merkle_rfc6962.json` are produced by an
//! independent Go implementation of RFC 6962 §2.1 in
//! `crates/test-harness/oracles/merkle-go/`, written straight from the RFC in
//! a different language than `kt-log`'s `tree.rs`. This test recomputes every
//! root and proof with `kt-log` and asserts byte-for-byte agreement with the
//! oracle. Because the two implementations share no code, agreement is real
//! evidence that both match the RFC rather than sharing a bug.
//!
//! For each proof the check is twofold: the *path bytes* `kt-log` generates
//! must equal the oracle's exactly (pins the sibling hashes, not just the
//! yes/no verdict), and `kt-log`'s verifier must accept the oracle's path.
//!
//! The fixture is embedded with `include_str!`, so a missing or unreadable
//! file is a compile error, and the size assertions below make an empty or
//! truncated corpus fail loudly rather than pass vacuously (§13: a green test
//! must mean the property ran). Regenerate the fixture with:
//!   cd crates/test-harness/oracles/merkle-go && go run . > \
//!     ../../../kt-log/tests/fixtures/merkle_rfc6962.json

use kt_log::tree::{
    consistency_path, inclusion_path, leaf_hash, root_hash, verify_consistency, verify_inclusion,
    Hash,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/merkle_rfc6962.json");

#[derive(Deserialize)]
struct FixtureFile {
    corpora: Vec<Corpus>,
}

#[derive(Deserialize)]
struct Corpus {
    name: String,
    leaves: Vec<String>,
    roots: Vec<RootCase>,
    inclusion: Vec<InclusionCase>,
    consistency: Vec<ConsistencyCase>,
}

#[derive(Deserialize)]
struct RootCase {
    tree_size: usize,
    root: String,
}

#[derive(Deserialize)]
struct InclusionCase {
    tree_size: usize,
    leaf_index: usize,
    path: Vec<String>,
}

#[derive(Deserialize)]
struct ConsistencyCase {
    first: usize,
    second: usize,
    path: Vec<String>,
}

fn hash(hex_str: &str) -> Hash {
    let bytes = hex::decode(hex_str).expect("fixture hash is valid hex");
    bytes
        .try_into()
        .expect("fixture hash is exactly 32 bytes (SHA-256)")
}

fn path(hexes: &[String]) -> Vec<Hash> {
    hexes.iter().map(|h| hash(h)).collect()
}

#[test]
fn kt_log_matches_go_oracle_on_all_fixture_corpora() {
    let file: FixtureFile = serde_json::from_str(FIXTURE).expect("fixture parses as JSON");

    // Guard against a vacuous pass: the fixture must actually carry work.
    assert!(!file.corpora.is_empty(), "fixture has no corpora");
    let mut total_roots = 0usize;
    let mut total_inclusion = 0usize;
    let mut total_consistency = 0usize;

    for corpus in &file.corpora {
        // Leaf entries are raw pre-hash bytes; kt-log's tree operates on the
        // leaf *hashes*, so hash each one the way KtLog::append would.
        let leaf_hashes: Vec<Hash> = corpus
            .leaves
            .iter()
            .map(|l| leaf_hash(&hex::decode(l).expect("leaf entry is valid hex")))
            .collect();

        assert!(
            !corpus.roots.is_empty() && !corpus.inclusion.is_empty(),
            "corpus {} is empty",
            corpus.name
        );

        // Roots for every tree size, including the empty tree.
        for rc in &corpus.roots {
            assert!(
                rc.tree_size <= leaf_hashes.len(),
                "corpus {}: root tree_size {} exceeds leaf count",
                corpus.name,
                rc.tree_size
            );
            assert_eq!(
                root_hash(&leaf_hashes[..rc.tree_size]),
                hash(&rc.root),
                "corpus {}: root mismatch at tree_size {}",
                corpus.name,
                rc.tree_size
            );
            total_roots += 1;
        }

        // Inclusion: generated path bytes must match the oracle, and the
        // oracle's path must verify under kt-log's verifier.
        for ic in &corpus.inclusion {
            let root = root_hash(&leaf_hashes[..ic.tree_size]);
            let oracle_path = path(&ic.path);

            let ours = inclusion_path(ic.leaf_index as u64, &leaf_hashes[..ic.tree_size]);
            assert_eq!(
                ours, oracle_path,
                "corpus {}: inclusion path bytes differ at size {} index {}",
                corpus.name, ic.tree_size, ic.leaf_index
            );
            assert!(
                verify_inclusion(
                    &leaf_hashes[ic.leaf_index],
                    ic.leaf_index as u64,
                    ic.tree_size as u64,
                    &oracle_path,
                    &root,
                ),
                "corpus {}: oracle inclusion path rejected at size {} index {}",
                corpus.name,
                ic.tree_size,
                ic.leaf_index
            );
            total_inclusion += 1;
        }

        // Consistency: same twofold check across every (first, second) pair.
        for cc in &corpus.consistency {
            let first_root = root_hash(&leaf_hashes[..cc.first]);
            let second_root = root_hash(&leaf_hashes[..cc.second]);
            let oracle_path = path(&cc.path);

            let ours = consistency_path(cc.first as u64, &leaf_hashes[..cc.second]);
            assert_eq!(
                ours, oracle_path,
                "corpus {}: consistency path bytes differ for {} -> {}",
                corpus.name, cc.first, cc.second
            );
            assert!(
                verify_consistency(
                    cc.first as u64,
                    cc.second as u64,
                    &oracle_path,
                    &first_root,
                    &second_root,
                ),
                "corpus {}: oracle consistency path rejected for {} -> {}",
                corpus.name,
                cc.first,
                cc.second
            );
            total_consistency += 1;
        }
    }

    // A concrete floor so a stripped-down fixture can never quietly pass: the
    // committed corpus covers the 8-leaf CT set plus the 16-leaf extended set.
    assert!(
        total_roots >= 25 && total_inclusion >= 130 && total_consistency >= 130,
        "fixture coverage shrank unexpectedly: roots={total_roots} inclusion={total_inclusion} consistency={total_consistency}"
    );
}
