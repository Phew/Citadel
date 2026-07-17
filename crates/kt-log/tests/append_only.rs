//! Property tests for the KT log's append-only invariant (PLAN.md §10, M1).
//!
//! The properties, over arbitrary leaf sequences and split points:
//!  1. Appending never invalidates an old STH: consistency old->new verifies.
//!  2. Old inclusion proofs keep verifying against the old STH forever.
//!  3. Any rewrite of history (mutating one already-committed leaf) makes the
//!     consistency proof fail — the log cannot equivocate undetected.
//!  4. Proofs are not transferable across mismatched sizes/roots.

use citadel_proto::credential::IdentityPublicKey;
use citadel_proto::ids::AccountId;
use citadel_proto::kt::KtLeaf;
use kt_log::{verify_consistency, verify_inclusion, verify_tree_head, KtLog, TreeHeadSigner};
use proptest::prelude::*;
use uuid::Uuid;

fn make_leaf(seed: u8, salt: u16) -> KtLeaf {
    KtLeaf {
        account_id: AccountId::from_uuid(Uuid::from_bytes([seed; 16])),
        handle: format!("user-{seed}-{salt}"),
        identity_pubkey: IdentityPublicKey([seed; 32]),
        appended_at: i64::from(salt),
    }
}

fn build_log(seeds: &[(u8, u16)]) -> (KtLog, Vec<KtLeaf>) {
    let mut log = KtLog::new();
    let leaves: Vec<KtLeaf> = seeds.iter().map(|&(s, t)| make_leaf(s, t)).collect();
    for l in &leaves {
        log.append(l);
    }
    (log, leaves)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Properties 1 + 2: appends never invalidate history.
    #[test]
    fn appends_preserve_old_heads_and_proofs(
        seeds in prop::collection::vec((any::<u8>(), any::<u16>()), 1..80),
        split in any::<prop::sample::Index>(),
    ) {
        let signer = TreeHeadSigner::from_seed(&[7u8; 32]);
        let first = 1 + split.index(seeds.len()); // 1..=len
        let (log, leaves) = build_log(&seeds);

        // Sign a head at the historical size `first`, as if signed back then.
        let (old_log, _) = build_log(&seeds[..first]);
        let old_sth = signer.sign_head(&old_log, 100);
        let new_sth = signer.sign_head(&log, 200);

        prop_assert!(verify_tree_head(&old_sth, &signer.public_key()));
        prop_assert!(verify_tree_head(&new_sth, &signer.public_key()));

        // Property 1: consistency old -> new always verifies.
        let cproof = log.consistency_proof(first as u64, log.size()).unwrap();
        prop_assert!(verify_consistency(&old_sth, &new_sth, &cproof));

        // Property 2: every leaf committed at `first` still proves inclusion
        // against BOTH the old head and the new head.
        for (i, leaf) in leaves[..first].iter().enumerate() {
            let old_proof = log.inclusion_proof(i as u64, first as u64).unwrap();
            prop_assert!(verify_inclusion(leaf, &old_proof, &old_sth));
            let new_proof = log.inclusion_proof(i as u64, log.size()).unwrap();
            prop_assert!(verify_inclusion(leaf, &new_proof, &new_sth));
        }
    }

    /// Property 3: rewriting any committed leaf breaks consistency with the
    /// head signed before the rewrite.
    #[test]
    fn history_rewrite_is_detected(
        seeds in prop::collection::vec((any::<u8>(), any::<u16>()), 2..60),
        victim in any::<prop::sample::Index>(),
        extra in prop::collection::vec((any::<u8>(), any::<u16>()), 0..10),
    ) {
        let signer = TreeHeadSigner::from_seed(&[7u8; 32]);
        let (honest_log, _) = build_log(&seeds);
        let old_sth = signer.sign_head(&honest_log, 100);

        // Adversarial log: same history but one leaf rewritten, then extended.
        let v = victim.index(seeds.len());
        let mut forged_seeds = seeds.clone();
        forged_seeds[v] = (
            forged_seeds[v].0.wrapping_add(1),
            forged_seeds[v].1.wrapping_add(1),
        );
        forged_seeds.extend_from_slice(&extra);
        let (forged_log, _) = build_log(&forged_seeds);
        let forged_sth = signer.sign_head(&forged_log, 200);

        let cproof = forged_log
            .consistency_proof(honest_log.size(), forged_log.size())
            .unwrap();
        // The forged log can produce internally-consistent proofs, but they
        // must NOT verify against the honestly-signed old head.
        prop_assert!(!verify_consistency(&old_sth, &forged_sth, &cproof));
    }

    /// Property 4: inclusion proofs do not transfer to other tree heads.
    #[test]
    fn inclusion_proofs_bind_to_their_head(
        seeds in prop::collection::vec((any::<u8>(), any::<u16>()), 2..60),
        idx in any::<prop::sample::Index>(),
    ) {
        let signer = TreeHeadSigner::from_seed(&[7u8; 32]);
        let (log, leaves) = build_log(&seeds);
        let full_sth = signer.sign_head(&log, 100);

        let i = idx.index(seeds.len().saturating_sub(1)); // a leaf before the last
        let smaller = (i + 1) as u64; // a strictly smaller tree containing leaf i
        prop_assume!(smaller < log.size());

        let small_proof = log.inclusion_proof(i as u64, smaller).unwrap();
        // Size-mismatched proof rejected against the full head.
        prop_assert!(!verify_inclusion(&leaves[i], &small_proof, &full_sth));
    }
}
