//! In-process F2/F4 flow tests: create -> add -> KT-verified join -> send/recv,
//! plus the INV-4 rejection path. These exercise the full citadel-core MLS
//! engine without a live delivery service (transport is elided; the ciphertext
//! bytes move in-process). The against-real-Postgres harness versions
//! (`f2_three_client_dm_creation`, `f4_send_receive_roundtrip`) live in
//! test-harness and drive these same code paths through the delivery service.

use crate::credential::CredentialError;
use crate::crypto::{Provider, CIPHERSUITE};
use crate::group::{DmGroup, GroupError, ReceiveOutcome};
use crate::testing::{make_identity, AllowList};
use citadel_proto::ids::GroupId;
use openmls::prelude::{BasicCredential, CredentialWithKey, KeyPackage};

/// F2 (create + add + join, all members KT-verified) then F4 (send/receive)
/// across three in-process clients, each with its own provider/state.
#[test]
fn f2_f4_three_client_dm_in_process() {
    let (pa, pb, pc) = (
        Provider::default(),
        Provider::default(),
        Provider::default(),
    );
    let ta = make_identity();
    let tb = make_identity();
    let tc = make_identity();

    // Joiners publish one KeyPackage each (F1 step 4 / F2 target fetch).
    let kp_b = tb.identity.new_key_package(&pb).unwrap();
    let kp_c = tc.identity.new_key_package(&pc).unwrap();

    // Initiator creates the DM and adds both in one commit (F2 step 2).
    let gid = GroupId::new();
    let mut group_a = DmGroup::create(&pa, &ta.identity, gid).unwrap();
    let verifier = AllowList::trusting(&[&ta, &tb, &tc]);
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b, kp_c], &verifier)
        .unwrap();
    assert_eq!(group_a.member_count(), 3);

    // Every member is KT-attested; both joiners verify all credentials (INV-4)
    // and join (F2 step 3).
    let mut group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();
    let mut group_c = DmGroup::join_from_welcome(&pc, &out.welcome_bytes, &verifier).unwrap();
    assert_eq!(group_b.member_count(), 3);
    assert_eq!(group_c.member_count(), 3);

    // F4: initiator sends; both recipients decrypt to the same plaintext.
    let plaintext = b"the operator cannot read this";
    let wire = group_a.send(&pa, &ta.identity, plaintext).unwrap();
    assert_eq!(
        group_b.receive(&pb, &wire, &verifier).unwrap(),
        ReceiveOutcome::Application(plaintext.to_vec())
    );
    assert_eq!(
        group_c.receive(&pc, &wire, &verifier).unwrap(),
        ReceiveOutcome::Application(plaintext.to_vec())
    );

    // A reply from B is readable by A (bidirectional).
    let reply = group_b.send(&pb, &tb.identity, b"nor this").unwrap();
    assert_eq!(
        group_a.receive(&pa, &reply, &verifier).unwrap(),
        ReceiveOutcome::Application(b"nor this".to_vec())
    );
}

/// INV-4: a joiner refuses to accept a group when any member credential is not
/// KT-attested. This is the join-side check; initiator-side swapped-KeyPackage
/// rejection is covered separately below.
#[test]
fn join_rejects_non_kt_attested_member() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity();
    let tb = make_identity();
    let kp_b = tb.identity.new_key_package(&pb).unwrap();

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let add_verifier = AllowList::trusting(&[&ta, &tb]);
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &add_verifier)
        .unwrap();

    // Verifier attests B but NOT the initiator A -> A's credential fails
    // verification during join, so B rejects the whole group.
    let verifier = AllowList::trusting(&[&tb]);
    match DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier) {
        Err(GroupError::MemberRejected(_)) => {}
        Err(other) => panic!("expected MemberRejected, got {other:?}"),
        Ok(_) => panic!("join must be rejected when a member is not KT-attested"),
    }
}

/// ADR-0005 §5: a dishonest server swaps the target device's fetched
/// KeyPackage for one whose credential is not KT-attested. The initiator
/// rejects before OpenMLS creates a commit, Welcome, or pending state.
#[test]
fn initiator_rejects_swapped_key_package_before_commit() {
    let (pa, pb, attacker_provider) = (
        Provider::default(),
        Provider::default(),
        Provider::default(),
    );
    let ta = make_identity();
    let tb = make_identity();
    let attacker = make_identity();
    let target_key_package = tb.identity.new_key_package(&pb).unwrap();
    let swapped_key_package = attacker
        .identity
        .new_key_package(&attacker_provider)
        .unwrap();
    let verifier = AllowList::trusting(&[&ta, &tb]);

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let initial_epoch = group_a.epoch();
    let err = group_a
        .add_members(&pa, &ta.identity, &[swapped_key_package], &verifier)
        .expect_err("unattested swapped KeyPackage must fail at the initiator");
    assert!(matches!(
        err,
        GroupError::MemberRejected(CredentialError::NotKtAttested)
    ));
    assert_eq!(group_a.epoch(), initial_epoch);
    assert_eq!(group_a.member_count(), 1);

    group_a
        .add_members(&pa, &ta.identity, &[target_key_package], &verifier)
        .expect("rejected input must leave no pending commit");
    assert_eq!(group_a.member_count(), 2);
}

#[test]
fn initiator_verifies_every_key_package_before_commit() {
    let (pa, pb, attacker_provider) = (
        Provider::default(),
        Provider::default(),
        Provider::default(),
    );
    let ta = make_identity();
    let tb = make_identity();
    let attacker = make_identity();
    let valid_key_package = tb.identity.new_key_package(&pb).unwrap();
    let rejected_key_package = attacker
        .identity
        .new_key_package(&attacker_provider)
        .unwrap();
    let verifier = AllowList::trusting(&[&ta, &tb]);
    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let initial_epoch = group_a.epoch();

    let err = group_a
        .add_members(
            &pa,
            &ta.identity,
            &[valid_key_package, rejected_key_package],
            &verifier,
        )
        .expect_err("one rejected member must reject the entire batch");
    assert!(matches!(
        err,
        GroupError::MemberRejected(CredentialError::NotKtAttested)
    ));
    assert_eq!(group_a.epoch(), initial_epoch);
    assert_eq!(group_a.member_count(), 1);
}

#[test]
fn initiator_rejects_leaf_key_not_bound_by_device_credential() {
    let (initiator_provider, leaf_provider) = (Provider::default(), Provider::default());
    let initiator = make_identity();
    let target = make_identity();
    let mismatched_leaf_signer = make_identity();
    let credential =
        BasicCredential::new(serde_json::to_vec(&target.identity.device_credential).unwrap());
    let credential_with_wrong_leaf_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: mismatched_leaf_signer
            .identity
            .credential_with_key
            .signature_key
            .clone(),
    };
    let mismatched_key_package = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &leaf_provider,
            &mismatched_leaf_signer.identity.signer,
            credential_with_wrong_leaf_key,
        )
        .unwrap()
        .key_package()
        .clone();
    let verifier = AllowList::trusting(&[&initiator, &target]);
    let mut group =
        DmGroup::create(&initiator_provider, &initiator.identity, GroupId::new()).unwrap();
    let initial_epoch = group.epoch();

    assert!(matches!(
        group.add_members(
            &initiator_provider,
            &initiator.identity,
            &[mismatched_key_package],
            &verifier,
        ),
        Err(GroupError::MemberRejected(
            CredentialError::DeviceKeyMismatch
        ))
    ));
    assert_eq!(group.epoch(), initial_epoch);
    assert_eq!(group.member_count(), 1);
}

/// M2 commit processing: a peer self-update remains pending locally until
/// simulated transport acceptance, while the recipient verifies and merges the
/// staged commit. Delivery ordering and conflict rebase remain M3.
#[test]
fn staged_self_update_commit_is_merged() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity();
    let tb = make_identity();
    let verifier = AllowList::trusting(&[&ta, &tb]);
    let kp_b = tb.identity.new_key_package(&pb).unwrap();

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &verifier)
        .unwrap();
    let mut group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();
    let old_epoch = group_b.epoch();

    let prepared = group_b.prepare_self_update(&pb, &tb.identity).unwrap();
    assert_eq!(prepared.proposed_epoch(), old_epoch + 1);
    assert_eq!(group_b.epoch(), old_epoch);

    assert_eq!(
        group_a
            .receive(&pa, prepared.commit_bytes(), &verifier)
            .unwrap(),
        ReceiveOutcome::CommitMerged {
            epoch: prepared.proposed_epoch()
        }
    );
    let proposed_epoch = prepared.proposed_epoch();
    group_b.confirm_self_update(&pb, &prepared).unwrap();
    assert_eq!(group_a.epoch(), proposed_epoch);
    assert_eq!(group_b.epoch(), proposed_epoch);

    let wire = group_b.send(&pb, &tb.identity, b"post-update").unwrap();
    assert_eq!(
        group_a.receive(&pa, &wire, &verifier).unwrap(),
        ReceiveOutcome::Application(b"post-update".to_vec())
    );
}

#[test]
fn staged_self_update_with_non_kt_attested_identity_is_not_merged() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity();
    let tb = make_identity();
    let full_verifier = AllowList::trusting(&[&ta, &tb]);
    let kp_b = tb.identity.new_key_package(&pb).unwrap();

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &full_verifier)
        .unwrap();
    let mut group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &full_verifier).unwrap();
    let prepared = group_b.prepare_self_update(&pb, &tb.identity).unwrap();
    let old_epoch = group_a.epoch();
    let rejecting_verifier = AllowList::trusting(&[&ta]);

    let err = group_a
        .receive(&pa, prepared.commit_bytes(), &rejecting_verifier)
        .expect_err("update-path identity must be KT-attested before merge");
    assert!(matches!(
        err,
        GroupError::MemberRejected(CredentialError::NotKtAttested)
    ));
    assert_eq!(group_a.epoch(), old_epoch);

    group_b.abort_self_update(&pb, &prepared).unwrap();
    let wire = group_b
        .send(&pb, &tb.identity, b"old epoch remains usable")
        .unwrap();
    assert_eq!(
        group_a.receive(&pa, &wire, &full_verifier).unwrap(),
        ReceiveOutcome::Application(b"old epoch remains usable".to_vec())
    );
}

#[test]
fn rejected_self_update_can_be_aborted_without_advancing_epoch() {
    let provider = Provider::default();
    let identity = make_identity();
    let mut group = DmGroup::create(&provider, &identity.identity, GroupId::new()).unwrap();
    let epoch = group.epoch();

    let prepared = group
        .prepare_self_update(&provider, &identity.identity)
        .unwrap();
    assert_eq!(prepared.proposed_epoch(), epoch + 1);
    assert_eq!(group.epoch(), epoch);
    group.abort_self_update(&provider, &prepared).unwrap();
    assert_eq!(group.epoch(), epoch);
}

#[test]
fn self_update_rejects_a_handle_from_another_group() {
    let (provider_a, provider_b) = (Provider::default(), Provider::default());
    let identity_a = make_identity();
    let identity_b = make_identity();
    let mut group_a = DmGroup::create(&provider_a, &identity_a.identity, GroupId::new()).unwrap();
    let mut group_b = DmGroup::create(&provider_b, &identity_b.identity, GroupId::new()).unwrap();
    let prepared_a = group_a
        .prepare_self_update(&provider_a, &identity_a.identity)
        .unwrap();
    let prepared_b = group_b
        .prepare_self_update(&provider_b, &identity_b.identity)
        .unwrap();

    assert!(matches!(
        group_a.confirm_self_update(&provider_a, &prepared_b),
        Err(GroupError::PreparedCommitMismatch)
    ));
    group_a
        .confirm_self_update(&provider_a, &prepared_a)
        .unwrap();
    group_b.abort_self_update(&provider_b, &prepared_b).unwrap();
}

#[test]
fn incoming_commit_is_deferred_while_self_update_is_pending() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity();
    let tb = make_identity();
    let verifier = AllowList::trusting(&[&ta, &tb]);
    let kp_b = tb.identity.new_key_package(&pb).unwrap();
    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &verifier)
        .unwrap();
    let mut group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();
    let initial_epoch = group_a.epoch();
    let prepared_a = group_a.prepare_self_update(&pa, &ta.identity).unwrap();
    let prepared_b = group_b.prepare_self_update(&pb, &tb.identity).unwrap();

    assert!(matches!(
        group_a.receive(&pa, prepared_b.commit_bytes(), &verifier),
        Err(GroupError::PendingCommitConflictDeferred)
    ));
    assert_eq!(group_a.epoch(), initial_epoch);
    group_a.abort_self_update(&pa, &prepared_a).unwrap();
    group_b.abort_self_update(&pb, &prepared_b).unwrap();
}

#[test]
fn proposal_bearing_commit_is_deferred_without_advancing_epoch() {
    let (pa, pb, pc) = (
        Provider::default(),
        Provider::default(),
        Provider::default(),
    );
    let ta = make_identity();
    let tb = make_identity();
    let tc = make_identity();
    let verifier = AllowList::trusting(&[&ta, &tb, &tc]);
    let kp_b = tb.identity.new_key_package(&pb).unwrap();
    let kp_c = tc.identity.new_key_package(&pc).unwrap();
    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let initial_add = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &verifier)
        .unwrap();
    let mut group_b =
        DmGroup::join_from_welcome(&pb, &initial_add.welcome_bytes, &verifier).unwrap();
    let initial_epoch = group_b.epoch();
    let proposal_bearing = group_a
        .add_members(&pa, &ta.identity, &[kp_c], &verifier)
        .unwrap();

    assert!(matches!(
        group_b.receive(&pb, &proposal_bearing.commit_bytes, &verifier),
        Err(GroupError::ProposalBearingCommitDeferred)
    ));
    assert_eq!(group_b.epoch(), initial_epoch);
    assert_eq!(group_b.member_count(), 2);
}

/// A ciphertext payload never contains the plaintext (INV-1 at the boundary
/// citadel-core hands to the delivery service).
#[test]
fn ciphertext_does_not_contain_plaintext() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity();
    let tb = make_identity();
    let kp_b = tb.identity.new_key_package(&pb).unwrap();

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let verifier = AllowList::trusting(&[&ta, &tb]);
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b], &verifier)
        .unwrap();
    let _group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();

    let marker = b"CANARY-PLAINTEXT-MARKER-9d1f";
    let wire = group_a.send(&pa, &ta.identity, marker).unwrap();
    assert!(
        !wire.windows(marker.len()).any(|w| w == marker),
        "plaintext marker leaked into ciphertext"
    );
}
