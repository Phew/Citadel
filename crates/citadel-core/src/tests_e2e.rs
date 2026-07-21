//! In-process F2/F4 flow tests: create -> add -> KT-verified join -> send/recv,
//! plus the INV-4 rejection path. These exercise the full citadel-core MLS
//! engine without a live delivery service (transport is elided; the ciphertext
//! bytes move in-process). The against-real-Postgres harness versions
//! (`f2_three_client_dm_creation`, `f4_send_receive_roundtrip`) live in
//! test-harness and drive these same code paths through K3's delivery-service.

use crate::crypto::Provider;
use crate::group::{DmGroup, GroupError};
use crate::testing::{make_identity, AllowList};
use citadel_proto::ids::GroupId;

/// F2 (create + add + join, all members KT-verified) then F4 (send/receive)
/// across three in-process clients, each with its own provider/state.
#[test]
fn f2_f4_three_client_dm_in_process() {
    let (pa, pb, pc) = (
        Provider::default(),
        Provider::default(),
        Provider::default(),
    );
    let ta = make_identity(&pa);
    let tb = make_identity(&pb);
    let tc = make_identity(&pc);

    // Joiners publish one KeyPackage each (F1 step 4 / F2 target fetch).
    let kp_b = tb.identity.new_key_package(&pb);
    let kp_c = tc.identity.new_key_package(&pc);

    // Initiator creates the DM and adds both in one commit (F2 step 2).
    let gid = GroupId::new();
    let mut group_a = DmGroup::create(&pa, &ta.identity, gid).unwrap();
    let out = group_a
        .add_members(&pa, &ta.identity, &[kp_b, kp_c])
        .unwrap();
    assert_eq!(group_a.member_count(), 3);

    // Every member is KT-attested; both joiners verify all credentials (INV-4)
    // and join (F2 step 3).
    let verifier = AllowList::trusting(&[&ta, &tb, &tc]);
    let mut group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();
    let mut group_c = DmGroup::join_from_welcome(&pc, &out.welcome_bytes, &verifier).unwrap();
    assert_eq!(group_b.member_count(), 3);
    assert_eq!(group_c.member_count(), 3);

    // F4: initiator sends; both recipients decrypt to the same plaintext.
    let plaintext = b"the operator cannot read this";
    let wire = group_a.send(&pa, &ta.identity, plaintext).unwrap();
    assert_eq!(group_b.receive(&pb, &wire).unwrap(), plaintext);
    assert_eq!(group_c.receive(&pc, &wire).unwrap(), plaintext);

    // A reply from B is readable by A (bidirectional).
    let reply = group_b.send(&pb, &tb.identity, b"nor this").unwrap();
    assert_eq!(group_a.receive(&pa, &reply).unwrap(), b"nor this");
}

/// INV-4: a joiner refuses to accept a group when any member credential is not
/// KT-attested (the swapped-KeyPackage / rogue-member shape). No group state is
/// created. The harness runs the full adversarial-DS version
/// (`adversarial_ds_swapped_keypackage_rejected`); this pins the core check.
#[test]
fn join_rejects_non_kt_attested_member() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity(&pa);
    let tb = make_identity(&pb);
    let kp_b = tb.identity.new_key_package(&pb);

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let out = group_a.add_members(&pa, &ta.identity, &[kp_b]).unwrap();

    // Verifier attests B but NOT the initiator A -> A's credential fails
    // verification during join, so B rejects the whole group.
    let verifier = AllowList::trusting(&[&tb]);
    match DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier) {
        Err(GroupError::MemberRejected(_)) => {}
        Err(other) => panic!("expected MemberRejected, got {other:?}"),
        Ok(_) => panic!("join must be rejected when a member is not KT-attested"),
    }
}

/// A ciphertext payload never contains the plaintext (INV-1 at the boundary
/// citadel-core hands to the delivery service).
#[test]
fn ciphertext_does_not_contain_plaintext() {
    let (pa, pb) = (Provider::default(), Provider::default());
    let ta = make_identity(&pa);
    let tb = make_identity(&pb);
    let kp_b = tb.identity.new_key_package(&pb);

    let mut group_a = DmGroup::create(&pa, &ta.identity, GroupId::new()).unwrap();
    let out = group_a.add_members(&pa, &ta.identity, &[kp_b]).unwrap();
    let verifier = AllowList::trusting(&[&ta, &tb]);
    let _group_b = DmGroup::join_from_welcome(&pb, &out.welcome_bytes, &verifier).unwrap();

    let marker = b"CANARY-PLAINTEXT-MARKER-9d1f";
    let wire = group_a.send(&pa, &ta.identity, marker).unwrap();
    assert!(
        !wire.windows(marker.len()).any(|w| w == marker),
        "plaintext marker leaked into ciphertext"
    );
}
